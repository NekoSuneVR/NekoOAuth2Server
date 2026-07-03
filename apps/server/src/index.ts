import { app } from "./app.js";
import { config } from "./config.js";

app.listen(config.port, () => {
  console.log(`NekoOAuth2Server listening on port ${config.port}`);
});
