const KeycloakClient = require('./keycloak');

module.exports = async function app(plugin) {
  const params = plugin.params || {};
  const client = new KeycloakClient({
    url: params.url,
    realm: params.realm,
    clientId: params.clientId,
    clientSecret: plugin.getPassword(params),
    authClientId: params.authClientId,
  });
  const connection = await client.testConnection();

  if (!connection.ok) {
    plugin.exit(1, connection.message);
    return;
  }

  plugin.log(connection.message, 1);

  async function getGroups(message) {
    const groups = await client.getGroupsFlat();

    plugin.log(`Keycloak: received groups: ${groups.length}`, 1);
    plugin.sendResponse({ ...message, groups }, 1);
  }

  async function getRoles(message) {
    const roles = await client.getRealmRoles();

    plugin.log(`Keycloak: received roles: ${roles.length}`, 1);
    plugin.sendResponse({ ...message, roles }, 1);
  }

  async function syncUsers(message) {
    const result = await client.getUsersFull({
      groupFilter: params.groupFilter || '',
      roleFilter: params.roleFilter || '',
      includeSubgroups: true,
    });
    const users = mapUsers(result.users);

    plugin.send({ type: 'syncUsers', data: users });
    plugin.log(`Keycloak: sent ${users.length} users to IntraSCADA`, 1);

    if (message.uuid) plugin.sendResponse({ ...message, imported: users.length }, 1);
  }

  async function authUser(message) {
    const tokens = await client.exchangeAuthorizationCode(message);
    const payload = await client.verifyJwt(tokens.access_token);
    const login = getLogin(payload);

    if (!login) {
      throw new Error('В access_token не найден логин пользователя');
    }

    plugin.log(`Keycloak: user authorized: ${login}`, 1);
    plugin.sendResponse(
      {
        ...message,
        login,
        data: buildTokenData(tokens),
      },
      1,
    );
  }

  async function refreshToken(message) {
    const tokens = await client.refreshTokens(message);
    const payload = await client.verifyJwt(tokens.access_token);
    const login = getLogin(payload);

    if (!login) {
      throw new Error(
        'В новом access_token не найден логин пользователя',
      );
    }

    plugin.log(`Keycloak: tokens refreshed for user: ${login}`, 1);
    plugin.sendResponse(
      {
        ...message,
        login,
        data: buildTokenData(tokens),
      },
      1,
    );
  }

  const handlers = { authUser, getGroups, getRoles, refreshToken, syncUsers };

  plugin.onCommand(async (message) => {
    const command = message.param || message.command || message.type;
    const handler = handlers[command];

    plugin.log(`Keycloak command: ${command || 'undefined'}`, 1);

    if (!handler) {
      plugin.log(`ERROR: Unknown command: ${command}`);
      return;
    }

    try {
      await handler(message);
    } catch (error) {
      const errorMessage = getErrorMessage(error);

      plugin.log(`Keycloak command error: ${errorMessage}`);
      if (message.uuid || message.type === 'authUser') {
        plugin.sendResponse({ ...message, message: errorMessage }, 0);
      }
    }
  });
};

function getErrorMessage(error) {
  return error && error.message
    ? error.message
    : String(error || 'Неизвестная ошибка');
}

function getLogin(payload) {
  if (!payload) return '';
  return payload.preferred_username || payload.username || payload.email || payload.sub || '';
}

function buildTokenData(tokens) {
  const expiresIn = Number(tokens.expires_in) || 0;
  const refreshExpiresIn = Number(tokens.refresh_expires_in) || 0;

  return {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_in: expiresIn,
    refresh_expires_in: refreshExpiresIn,
    token_type: tokens.token_type || 'Bearer',
    refresh_in: expiresIn ? Math.max(expiresIn - 30, 1) : 0,
  };
}

function mapUsers(users) {
  return (users || []).map((user) => ({
    dn: user.id,
    guid: user.id,
    login: user.username,
    name: [user.firstName, user.lastName].filter(Boolean).join(' ').trim() || user.username,
    email: user.email || '',
    groups: (user.groups || [])
      .map((group) => group.path || group.name)
      .filter(Boolean)
      .sort(),
    roles: (user.roles || []).map(({ id, name }) => ({ id, name })),
  }));
}
