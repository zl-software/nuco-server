// Entry point for the Nuco relay. The full bootstrap (config, storage, ws + http,
// push sender) is wired up in the server skeleton milestone. This placeholder keeps
// the package importable and confirms the shared contract resolves.

import { PROTOCOL_VERSION_STRING } from '@nuco/protocol';

console.log(`nuco-server: shared protocol ${PROTOCOL_VERSION_STRING} loaded.`);
