const http = require('http');
const https = require('https');
const crypto = require('crypto');

const DEFAULT_TIMEOUT = 15000;
const PAGE_SIZE = 1000;
const JWKS_CACHE_TTL = 5 * 60 * 1000;
const JWT_ALGORITHMS = {
  RS256: 'RSA-SHA256',
  RS384: 'RSA-SHA384',
  RS512: 'RSA-SHA512',
};
const encode = (value) => encodeURIComponent(value);

class KeycloakClient {
  constructor({ url, realm, clientId, clientSecret, authClientId }) {
    this.url = String(url || '').replace(/\/+$/, '');
    this.realm = String(realm || '').trim();
    this.clientId = String(clientId || '').trim();
    this.clientSecret = String(clientSecret || '');
    this.authClientId = String(authClientId || '').trim();
    this.jwks = null;
    this.jwksLoadedAt = 0;
  }

  validate() {
    if (!this.url) throw new Error('Не задан Keycloak URL');
    if (!this.realm) throw new Error('Не задан Realm');
    if (!this.clientId) throw new Error('Не задан Client ID');
    if (!this.clientSecret) throw new Error('Не задан Client secret');
  }

  validateAuthData(data) {
    if (!data.code) throw new Error('Не передан authorization code');
    if (!data.codeVerifier) throw new Error('Не передан code_verifier');
    if (!data.redirectUri) {
      throw new Error('Не задан Redirect URI для Authorization Code');
    }
    if (!data.clientId) throw new Error('Не задан Public Client ID');
  }

  validateRefreshData(data) {
    if (!data.refreshToken) throw new Error('Не передан refresh_token');
    if (!data.clientId) throw new Error('Не задан Public Client ID');
  }

  request(method, path, options = {}) {
    return new Promise((resolve, reject) => {
      let target;

      try {
        target = new URL(`${this.url}${path}`);
      } catch (error) {
        reject(new Error(`Некорректный Keycloak URL: ${this.url}`));
        return;
      }

      const transport = target.protocol === 'https:' ? https : http;
      const body = options.body || '';
      const headers = { ...(options.headers || {}) };

      if (body) headers['Content-Length'] = Buffer.byteLength(body);

      const request = transport.request(
        {
          protocol: target.protocol,
          hostname: target.hostname,
          port: target.port || undefined,
          path: `${target.pathname}${target.search}`,
          method,
          headers,
          timeout: options.timeout || DEFAULT_TIMEOUT,
        },
        (response) => {
          let responseBody = '';

          response.setEncoding('utf8');
          response.on('data', (chunk) => { responseBody += chunk; });
          response.on('end', () => {
            const statusCode = response.statusCode || 0;

            if (statusCode < 200 || statusCode >= 300) {
              reject(new Error(
                `${method} ${path}: HTTP ${statusCode}${responseBody ? ` ${responseBody}` : ''}`,
              ));
              return;
            }

            if (!responseBody) {
              resolve(null);
              return;
            }

            try {
              resolve(JSON.parse(responseBody));
            } catch (error) {
              reject(new Error(`${method} ${path}: invalid JSON response`));
            }
          });
        },
      );

      request.on('timeout', () => request.destroy(new Error(`${method} ${path}: timeout`)));
      request.on('error', reject);
      if (body) request.write(body);
      request.end();
    });
  }

  get(path, token) {
    return this.request('GET', path, {
      headers: { Accept: 'application/json', Authorization: `Bearer ${token}` },
    });
  }

  async getAccessToken() {
    this.validate();

    const path = `/realms/${encode(this.realm)}/protocol/openid-connect/token`;
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.clientId,
      client_secret: this.clientSecret,
    }).toString();
    const data = await this.request('POST', path, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });

    if (!data || !data.access_token) throw new Error('Keycloak не вернул access_token');
    return data.access_token;
  }

  async exchangeAuthorizationCode(source = {}) {
    const payload = source.data && typeof source.data === 'object' ? source.data : {};
    const data = {
      code: source.code || payload.code || '',
      codeVerifier: source.code_verifier
        || source.verifier
        || payload.code_verifier
        || payload.verifier
        || '',
      redirectUri: source.redirect_uri || payload.redirect_uri || '',
      clientId: source.client_id
        || source.clientId
        || payload.client_id
        || payload.clientId
        || this.authClientId,
    };

    this.validateAuthData(data);

    const path = `/realms/${encode(this.realm)}/protocol/openid-connect/token`;
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: data.clientId,
      code: data.code,
      redirect_uri: data.redirectUri,
      code_verifier: data.codeVerifier,
    }).toString();
    const tokens = await this.request('POST', path, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });

    if (!tokens || !tokens.access_token) {
      throw new Error('Keycloak не вернул access_token');
    }
    if (!tokens.refresh_token) throw new Error('Keycloak не вернул refresh_token');

    return tokens;
  }

  async refreshTokens(source = {}) {
    const payload = source.data && typeof source.data === 'object' ? source.data : {};
    const data = {
      refreshToken: source.refresh_token || payload.refresh_token || '',
      clientId: source.client_id
        || source.clientId
        || payload.client_id
        || payload.clientId
        || this.authClientId,
    };

    this.validateRefreshData(data);

    const path = `/realms/${encode(this.realm)}/protocol/openid-connect/token`;
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: data.clientId,
      refresh_token: data.refreshToken,
    }).toString();
    const tokens = await this.request('POST', path, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });

    if (!tokens || !tokens.access_token) {
      throw new Error('Keycloak не вернул новый access_token');
    }

    return {
      ...tokens,
      refresh_token: tokens.refresh_token || data.refreshToken,
    };
  }

  parseJwtPart(value, errorMessage) {
    try {
      const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
      const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
      return JSON.parse(Buffer.from(normalized + padding, 'base64').toString('utf8'));
    } catch (error) {
      throw new Error(errorMessage);
    }
  }

  parseJwt(token) {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) throw new Error('Некорректный JWT access_token');

    return this.parseJwtPart(parts[1], 'Не удалось разобрать JWT access_token');
  }

  async getJwks(forceReload = false) {
    const cacheAlive = Date.now() - this.jwksLoadedAt < JWKS_CACHE_TTL;

    if (!forceReload && this.jwks && cacheAlive) return this.jwks;

    const path = `/realms/${encode(this.realm)}/protocol/openid-connect/certs`;
    const data = await this.request('GET', path, {
      headers: { Accept: 'application/json' },
    });

    if (!data || !Array.isArray(data.keys)) {
      throw new Error('Keycloak вернул некорректный JWKS');
    }

    this.jwks = data.keys;
    this.jwksLoadedAt = Date.now();
    return this.jwks;
  }

  async getJwtKey(kid) {
    let keys = await this.getJwks();
    let key = keys.find((item) => item.kid === kid);

    if (!key) {
      keys = await this.getJwks(true);
      key = keys.find((item) => item.kid === kid);
    }

    if (!key) throw new Error(`Не найден ключ подписи JWT: ${kid}`);
    return key;
  }

  async verifyJwt(token) {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) throw new Error('Некорректный JWT access_token');

    const header = this.parseJwtPart(
      parts[0],
      'Не удалось разобрать заголовок JWT',
    );
    const payload = this.parseJwtPart(
      parts[1],
      'Не удалось разобрать JWT access_token',
    );

    if (!header.kid) throw new Error('В JWT отсутствует kid');
    if (!JWT_ALGORITHMS[header.alg]) {
      const algorithm = header.alg || 'undefined';
      throw new Error(
        `Неподдерживаемый алгоритм подписи JWT: ${algorithm}`,
      );
    }

    const jwk = await this.getJwtKey(header.kid);
    const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    const signature = base64UrlToBuffer(parts[2]);
    const signedData = Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8');
    const valid = crypto.verify(
      JWT_ALGORITHMS[header.alg],
      signedData,
      publicKey,
      signature,
    );

    if (!valid) throw new Error('Некорректная подпись JWT access_token');

    return payload;
  }

  async testConnection() {
    try {
      const token = await this.getAccessToken();
      const users = await this.get(`/admin/realms/${encode(this.realm)}/users?max=1`, token);

      if (!Array.isArray(users)) {
        throw new Error(
          'Keycloak вернул некорректный список пользователей',
        );
      }
      return { ok: true, message: 'Подключение к Keycloak успешно' };
    } catch (error) {
      return { ok: false, message: getErrorMessage(error) };
    }
  }

  async getPaged(pathFactory, token) {
    const result = [];
    let first = 0;

    while (true) {
      const page = await this.get(pathFactory(first, PAGE_SIZE), token);

      if (!Array.isArray(page) || !page.length) break;
      result.push(...page);
      if (page.length < PAGE_SIZE) break;
      first += PAGE_SIZE;
    }

    return result;
  }

  getUsers(token) {
    return this.getPaged(
      (first, max) => `/admin/realms/${encode(this.realm)}/users?first=${first}&max=${max}`,
      token,
    );
  }

  getUserGroups(userId, token) {
    return this.get(`/admin/realms/${encode(this.realm)}/users/${encode(userId)}/groups`, token);
  }

  getUserRealmRoles(userId, token) {
    const path = `/admin/realms/${encode(this.realm)}/users/${encode(userId)}/role-mappings/realm`;
    return this.get(path, token);
  }

  async getRealmRoles(token) {
    const accessToken = token || await this.getAccessToken();
    const roles = await this.getPaged(
      (first, max) => `/admin/realms/${encode(this.realm)}/roles?first=${first}&max=${max}`,
      accessToken,
    );

    return roles.map(({ id, name }) => ({ id, name }));
  }

  getGroups(token) {
    return this.getPaged(
      (first, max) => `/admin/realms/${encode(this.realm)}/groups`
        + `?briefRepresentation=false&first=${first}&max=${max}`,
      token,
    );
  }

  async getGroupsFlat(token) {
    const accessToken = token || await this.getAccessToken();
    return flattenGroups(await this.getGroups(accessToken));
  }

  getGroupMembers(groupId, token) {
    return this.getPaged(
      (first, max) => `/admin/realms/${encode(this.realm)}/groups/${encode(groupId)}`
        + `/members?first=${first}&max=${max}`,
      token,
    );
  }

  async getUsersByGroups(groupFilter, token, includeSubgroups = true) {
    const filters = normalizeFilter(groupFilter);
    const allGroups = await this.getGroupsFlat(token);
    const selectedGroups = resolveSelectedGroups(allGroups, filters, includeSubgroups);

    if (filters.length && !selectedGroups.length) {
      throw new Error(`Не найдены группы Keycloak: ${filters.join(', ')}`);
    }

    const memberLists = await Promise.all(
      selectedGroups.map((group) => this.getGroupMembers(group.id, token)),
    );
    const usersById = new Map();

    memberLists.flat().forEach((user) => usersById.set(user.id, user));
    return { users: [...usersById.values()], selectedGroups };
  }

  async getUserFull(user, token) {
    const [groups = [], roles = []] = await Promise.all([
      this.getUserGroups(user.id, token),
      this.getUserRealmRoles(user.id, token),
    ]);

    return {
      id: user.id,
      username: user.username,
      firstName: user.firstName || '',
      lastName: user.lastName || '',
      email: user.email || '',
      emailVerified: Boolean(user.emailVerified),
      enabled: Boolean(user.enabled),
      groups: groups.map(({ id, name, path }) => ({ id, name, path })),
      roles: roles.map(({ id, name }) => ({ id, name })),
    };
  }

  async getUsersFull(options = {}) {
    const token = await this.getAccessToken();
    const groupFilters = normalizeFilter(options.groupFilter);
    const result = groupFilters.length
      ? await this.getUsersByGroups(groupFilters, token, options.includeSubgroups !== false)
      : { users: await this.getUsers(token), selectedGroups: [] };
    const users = await Promise.all(result.users.map((user) => this.getUserFull(user, token)));
    const roleFilters = normalizeFilter(options.roleFilter);
    const filteredUsers = users
      .map((user) => ({ ...user, roles: filterRoles(user.roles, roleFilters) }))
      .filter((user) => !roleFilters.length || user.roles.length);

    return { users: filteredUsers, selectedGroups: result.selectedGroups };
  }
}

module.exports = KeycloakClient;

function getErrorMessage(error) {
  return error && error.message
    ? error.message
    : String(error || 'Неизвестная ошибка');
}

function normalizeFilter(filter) {
  if (!filter) return [];

  const values = Array.isArray(filter) ? filter : String(filter).split(',');
  return values.map((value) => String(value || '').trim()).filter(Boolean);
}

function filterRoles(roles, roleFilter) {
  const filters = normalizeFilter(roleFilter);
  if (!filters.length) return roles || [];

  return (roles || []).filter(({ id, name }) =>
    filters.includes(id) || filters.includes(name));
}


function base64UrlToBuffer(value) {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(normalized + padding, 'base64');
}

function flattenGroups(groups, parentPath = '') {
  return (groups || []).reduce((result, group) => {
    const path = group.path || `${parentPath}/${group.name}`.replace(/\/+/g, '/');
    const item = { id: group.id, name: group.name, path };
    const subGroups = flattenGroups(group.subGroups, path);

    return result.concat(item, subGroups);
  }, []);
}

function resolveSelectedGroups(allGroups, groupFilter, includeSubgroups = true) {
  const selected = new Map();

  normalizeFilter(groupFilter).forEach((filter) => {
    allGroups
      .filter((group) => group.id === filter || group.path === filter || group.name === filter)
      .forEach((group) => {
        selected.set(group.id, group);
        if (!includeSubgroups) return;

        const prefix = group.path.endsWith('/') ? group.path : `${group.path}/`;
        allGroups
          .filter((candidate) => candidate.path.startsWith(prefix))
          .forEach((candidate) => selected.set(candidate.id, candidate));
      });
  });

  return [...selected.values()];
}
