const util = require('util');
const app = require('./app');

function getOptions() {
  try {
    return JSON.parse(process.argv[2]);
  } catch (error) {
    return {};
  }
}

(async () => {
  let plugin;

  try {
    const { pluginapi = 'ih-plugin-api' } = getOptions();

    plugin = require(`${pluginapi}/index.js`)();
    plugin.log('Keycloak plugin has started.', 1);
    plugin.params = await plugin.params.get();

    await app(plugin);
  } catch (error) {
    if (plugin) {
      plugin.exit(8, `ERROR: ${util.inspect(error)}`);
      return;
    }

    if (process.send) process.send({ type: 'debug', txt: `ERROR: ${util.inspect(error)}` });
    process.exit(255);
  }
})();
