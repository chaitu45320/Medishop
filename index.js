// index.js — Railway entry point redirect
// Railway sometimes ignores Procfile and uses "main" from package.json.
// This file ensures the app starts regardless of which file Railway picks.
require('./server.js');
