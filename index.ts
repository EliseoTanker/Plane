let dev = true;
import express from "express";
const app = express();
import * as https from "https";
import * as fs from "fs";
import * as crypto from "crypto";
import * as path from "path";
import { credentialsAuth, lockfileAuth, agent } from "./val-auth.js";
import axios from "axios";
import chalk from "chalk";
import readlineSync from "readline-sync";
import Auth from "basic-auth";
import rateLimit from "express-rate-limit";
import "dotenv/config";
function file_hash() {
  const fileBuffer = fs.readFileSync(path.basename(new URL("", import.meta.url).pathname));
  const hashSum = crypto.createHash("md5");
  hashSum.update(fileBuffer);
  const hex = hashSum.digest("hex");
  return hex;
}
async function check_version() {
  let hash = await file_hash();
  let github_hash = (await axios.get("https://raw.githubusercontent.com/EliseoTanker/PWA-Typescript/main/file-hash-thing.json")).data.hash;
  if (github_hash !== hash) {
    console.log(chalk.red(`Your version of the application appears to be outdated (Current MD5 hash ${hash}, expected hash ${github_hash})`));
  }
}
if (!dev) await check_version();
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: true
});
if (dev) {
  var webUsername = process.env.AUTH_USERNAME;
  var webPassword = process.env.AUTH_PASSWORD;
} else {
  var webUsername = readlineSync.question("Website username: ");
  var webPassword = readlineSync.question("Website password: ", {
    hideEchoBack: true
  });
}
const auth = function (res, req, next) {
  var user = Auth(res);
  if (!user || webUsername !== user.name || webPassword !== user.pass) {
    req.set("WWW-Authenticate", 'Basic realm="example"');
    return req.status(401).send();
  }
  return next();
};
let invAgentsReq = await axios.get("https://valorant-api.com/v1/agents?isPlayableCharacter=true");
let invAgents = { "": "(In Range)" };
for (let i = 0; i < invAgentsReq.data.data.length; i++) {
  invAgents[invAgentsReq.data.data[i].uuid] = invAgentsReq.data.data[i].displayName.split(" ")[0];
}

let agentsReq = await axios.get("https://valorant-api.com/v1/agents?isPlayableCharacter=true");
let agents = {};
for (let i = 0; i < agentsReq.data.data.length; i++) {
  agents[agentsReq.data.data[i].displayName.split(" ")[0].toLowerCase()] = agentsReq.data.data[i].uuid;
}

process.on("uncaughtException", function (err) {
  if (dev) console.log(err);
});
app.use(limiter).use(express.static("public")).use(express.json());
async function axiosGet(url: string, headers: any) {
  if (headers === "JWT") {
    var res = await axios.get(url, {
      headers: {
        "X-Riot-Entitlements-JWT": entitlements.token,
        "X-Riot-ClientVersion": version,
        "X-Riot-ClientPlatform": "ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9TVmVyc2lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIlVua25vd24iDQp9",
        Authorization: "Bearer " + entitlements.access_token
      },
      httpsAgent: new https.Agent({
        rejectUnauthorized: false
      })
    });
  } else {
    var res = await axios.get(url, {
      headers: headers,
      httpsAgent: new https.Agent({
        rejectUnauthorized: false
      })
    });
  }
  return res.data;
}
async function authPost(url: string, body?: any, method?: string) {
  if (!body) {
    var body: any = {};
  }
  if (!method) {
    var method = "post";
  }
  let config = {
    headers: {
      "X-Riot-Entitlements-JWT": entitlements.token,
      Authorization: "Bearer " + entitlements.access_token,
      "X-Riot-ClientVersion": version,
      "X-Riot-ClientPlatform": "ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9TVmVyc2lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIlVua25vd24iDQp9"
    }
  };
  await axios[method](url, body, config);
}
type Entitlements = {
  access_token: string;
  entitlements?: [];
  issuer?: string;
  id_token?: string;
  expires_in?: number;
  token: string;
  subject: string;
};
let region: any = ["na", "na"];
if (dev) {
  var authMode = process.env.AUTH_MODE;
} else var authMode = readlineSync.question('\nAuth mode ("Credentials" or "Lockfile"): ');
if (authMode === "Credentials") {
  if (dev) {
    var entitlements: Entitlements = await credentialsAuth(process.env.VAL_USERNAME, process.env.VAL_PASSWORD);
  } else {
    let username = readlineSync.question("Riot username: ");
    let password = readlineSync.question("Password: ", {
      hideEchoBack: true
    });
    var entitlements: Entitlements = await credentialsAuth(username, password);
  }
  var regions = (
    await axios.put(
      "https://riot-geo.pas.si.riotgames.com/pas/v1/product/valorant",
      { id_token: entitlements.id_token },
      {
        headers: {
          Authorization: `Bearer ${entitlements.access_token}`
        },
        httpsAgent: agent
      }
    )
  ).data.affinities;
  region = [regions.live, regions.pbe];
} else if (authMode === "Lockfile") {
  var entitlements: Entitlements = await lockfileAuth();
  if (dev) {
    region = process.env.REGIONS.split(" ");
  } else {
    region = readlineSync.question("Region (Twice, separated by a space. E.g.: na na, if region = br/latam set shard first then na): ");
  }
} else {
  console.log(chalk.red('Invalid auth type (Must be "Lockfile" or "Credentials")'));
  process.exit(1);
}
let version = (await axios.get("https://valorant-api.com/v1/version")).data.data.riotClientVersion;
async function getPreGameID() {
  let preGameMatchID = await axiosGet(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/pregame/v1/players/${entitlements.subject}`, "JWT").catch(function () {
    console.log("Pregame match not found");
    return;
  });
  if (preGameMatchID) return preGameMatchID.MatchID;
}
async function getCoreGameID() {
  let CoreGameMatchID = await axiosGet(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/core-game/v1/players/${entitlements.subject}`, "JWT").catch(function (err) {
    console.log("Match not found");
    return;
  });
  if (CoreGameMatchID) return CoreGameMatchID.MatchID;
}
async function getPartyID() {
  let partyReq = await axiosGet(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/players/${entitlements.subject}`, "JWT").catch(function (err) {});
  if (partyReq) return partyReq.CurrentPartyID;
}
app.post("/api/party/gamemode", async (req, res) => {
  let partyID = await getPartyID();
  if (!partyID) {
    let message = "Party not found";
    res.statusCode = 404;
    res.send({ error: message });
    console.log(message);
    return;
  }
  await authPost(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/parties/${partyID}/queue/`, {
    queueID: req.body.id
  }).catch((err) => {
    if (err.response.data.httpStatus === 400) {
      res.statusCode = 400;
      let message = "Can't change gamemode while in custom game";
      res.send({ error: message });
      console.log(message);
    }
  });
  console.log(`Gamemode selected: ${req.body.id}`);
  res.send({ gamemode: req.body.id });
});
app.post("/api/party/ready", async (req, res) => {
  let partyReq = await axiosGet(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/players/${entitlements.subject}`, "JWT");
  if (req.body.ready === true) var ready = true;
  if (req.body.ready === false) var ready = false;
  await authPost(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/parties/${partyReq.CurrentPartyID}/members/${entitlements.subject}/setReady`, {
    ready: ready
  });
});
app.post("/api/party/a11y", async (req, res) => {
  let partyReq = await axiosGet(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/players/${entitlements.subject}`, "JWT");
  if (req.body.status === true) var a11y = "CLOSED";
  if (req.body.status === false) var a11y = "OPEN";
  await authPost(
    `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/parties/${partyReq.CurrentPartyID}/accessibility`,

    {
      accessibility: a11y
    }
  );
});
app.post("/api/party/queue", async (req, res) => {
  let partyReq = await axiosGet(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/players/${entitlements.subject}`, "JWT");
  authPost(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/parties/${partyReq.CurrentPartyID}/${req.body.type === "Custom" ? "startcustomgame" : "matchmaking/join"}`).catch(function (err) {
    console.log(err.response.data);
  });
  console.log(req.body.type === "Custom" ? "Started custom game" : "Joined matchmaking");
});
app.post("/api/party/leave-queue", async (req, res) => {
  let partyReq = await axiosGet(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/players/${entitlements.subject}`, "JWT").catch(function () {
    console.log(`Party request returned an error`);
  });
  await authPost(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/parties/${partyReq.CurrentPartyID}/matchmaking/leave/`).catch(function (err) {
    console.log(err.response.data);
  });
  res.send({ success: true });
  console.log("Left matchmaking");
});
app.post("/api/select", async (req, res) => {
  let PreGameID = await getPreGameID();
  if (!PreGameID) return (res.statusCode = 404), res.send({ error: "Match not found" });
  let pröAgent = agents[invAgents[req.body.agentID].toLowerCase()];
  await authPost(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/pregame/v1/matches/${PreGameID}/select/${pröAgent}`).catch(function (err) {
    console.log(err.response.data);
  });
  console.log(`Selected Agent: ${invAgents[req.body.agentID]}`);
  res.send({
    succes: true,
    agent: invAgents[req.body.agentID]
  });
});
app.post("/api/lock", async (req, res) => {
  let PreGameID = await getPreGameID();
  if (!PreGameID) return (res.statusCode = 404), res.send({ error: "Match not found" });
  let MatchDetails = await axiosGet(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/pregame/v1/matches/${PreGameID}`, "JWT");
  let MatchPlayers = MatchDetails.Teams[0].Players;
  for (let i = 0; i < MatchPlayers.length; i++) {
    let matchSubject = MatchPlayers[i].Subject;
    if (matchSubject === entitlements.subject) {
      if (MatchDetails.Teams[0].Players[i].CharacterID == "") console.log("No agent selected");
      else {
        let selectedAgent = MatchDetails.Teams[0].Players[i].CharacterID;
        authPost(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/pregame/v1/matches/${PreGameID}/lock/${selectedAgent}`).catch(function (err) {
          console.log(`${err.response.data.httpStatus} ${err.response.data.message}`);
        });
        res.send({ succes: true, agentSelected: invAgents[selectedAgent] });
      }
    }
  }
});
let Skins = {
  Vandal: "9c82e19d-4575-0200-1a81-3eacf00cf872",
  Classic: "29a0cfab-485b-f5d5-779a-b59f85e204a8"
};
app.post("/api/loadouts", async (req, res) => {
  if (req.body.type === "PreGame") {
    res.send({ implemented: false });
  } else if (req.body.type === "CoreGame") {
    let CoreGameID = await getCoreGameID();
    if (!CoreGameID) return (res.statusCode = 404), res.send({ error: "Match not found" });
    let matchDetails = await axiosGet(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/core-game/v1/matches/${CoreGameID}`, "JWT").catch(function (err) {
      if (err.response.status === 404) {
        console.log("Error: Match not found");
      }
    });
    let matchPlayers = matchDetails.Players;
    let arr = [];
    for (let i = 0; i < matchPlayers.length; i++) {
      //Player
      let name: any = await axios.put(`https://pd.${region[1]}.a.pvp.net/name-service/v2/players/`, [matchPlayers[i].Subject]).catch(function (err) {
        console.log(err.response.status);
      });
      name = `${name.data[0].GameName}#${name.data[0].TagLine}`;
      let agent = invAgents[matchPlayers[i].CharacterID];
      //Skin
      let loadout = await axiosGet(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/core-game/v1/matches/${CoreGameID}/loadouts`, "JWT");
      //Match Skin and push
      let weaponsJSON = await axios.get("https://valorant-api.com/v1/weapons");
      /*
      let playerSkin =
       loadout.Loadouts[i].Loadout.Items[Skins[process.env.SKINS_WEAPON]]
         .Sockets["bcef87d6-209b-46c6-8b19-fbe40bd95abc"].Item.ID;
      Skin = weaponsJSON["data"]["data"].find(
        (w) => w.uuid === Skins[process.env.SKINS_WEAPON]
      );
      Skin = Skin.skins.find((s) => s.uuid === playerSkin).displayName;
      arr.push(`${name} : ${Skin}: ${agent}`);
      */
      let Skin = loadout.Loadouts[i].Loadout.Items[Skins["Vandal"]].Sockets["bcef87d6-209b-46c6-8b19-fbe40bd95abc"].Item.ID;
      for (let i = 0; i < weaponsJSON["data"]["data"].length; i++) {
        if (weaponsJSON.data.data[i].uuid === Skins["Vandal"]) {
          for (let x = 0; x < weaponsJSON.data.data[i].skins.length; x++) {
            if (Skin === weaponsJSON.data.data[i].skins[x].uuid) {
              Skin = weaponsJSON.data.data[i].skins[x].displayName;
              arr.push(`${name} : ${Skin}: ${agent}`);
            }
          }
        }
      }
    }
    console.log(arr.join("\n"));
    res.send({ skins: arr });
  }
});
app.post("/api/exit", async (req, res) => {
  if (req.body.type === "PreGame") {
    let PreGameID = await getPreGameID();
    if (!PreGameID) return (res.statusCode = 404), res.send({ error: "Match not found" });
    await authPost(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/pregame/v1/matches/${PreGameID}/quit`).catch((err) => {
      console.log(err.response.data);
    });
  } else if (req.body.type === "CoreGame") {
    let coreGameID = await getCoreGameID();
    if (!coreGameID) return (res.statusCode = 404), res.send({ error: "Match not found" });
    await authPost(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/core-game/v1/players/${entitlements.subject}/disassociate/${coreGameID}`).catch((err) => {
      console.log(err.response.data);
    });
  } else if (req.body.type === "Party") {
    await axios
      .delete(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/players/${entitlements.subject}`, {
        headers: {
          "X-Riot-Entitlements-JWT": entitlements.token,
          Authorization: "Bearer " + entitlements.access_token
        }
      })
      .catch((err) => {
        console.log(err.response.data);
      });
    res.send({ status: 200 });
  }
});
app.post("/api/store", async (req, res) => {
  let SkinOffers = (await axiosGet(`https://pd.${region[1]}.a.pvp.net/store/v2/storefront/${entitlements.subject}`, "JWT")).SkinsPanelLayout.SingleItemOffers;
  let skinsJSON = await axios.get("https://valorant-api.com/v1/weapons/skins");
  let arr = [];
  for (let i = 0; i < SkinOffers.length; i++) {
    let Skin = SkinOffers[i];
    for (let i = 0; i < skinsJSON["data"]["data"].length; i++) {
      for (let x = 0; x < skinsJSON.data.data[i].levels.length; x++) {
        if (skinsJSON.data.data[i].levels[x].uuid === Skin) {
          arr.push(skinsJSON.data.data[i].levels[x].displayName);
        }
      }
    }
  }
  res.send({ skins: arr });
});
const Tiers: any = {
  0: "Unrated",
  1: "Unknown 1",
  2: "Unknown 2",
  3: "Iron 1",
  4: "Iron 2",
  5: "Iron 3",
  6: "Bronze 1",
  7: "Bronze 2",
  8: "Bronze 3",
  9: "Silver 1",
  10: "Silver 2",
  11: "Silver 3",
  12: "Gold 1",
  13: "Gold 2",
  14: "Gold 3",
  15: "Platinum 1",
  16: "Platinum 2",
  17: "Platinum 3",
  18: "Diamond 1",
  19: "Diamond 2",
  20: "Diamond 3",
  21: "Immortal",
  22: "Immortal",
  23: "Immortal",
  24: "Radiant"
};
app.post("/api/ranks", async (req, res) => {
  let seasonID = "3e47230a-463c-a301-eb7d-67bb60357d4f";
  if (req.body.type === "PreGame") {
    let PreGameID = await getPreGameID();
    if (!PreGameID) return (res.statusCode = 404), res.send({ error: "Match not found" });
    let matchDetails = await axiosGet(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/pregame/v1/matches/${PreGameID}`, "JWT");
    let matchPlayers = matchDetails.Teams[0].Players;
    let arr = [];
    for (let i = 0; i < matchPlayers.length; i++) {
      let puuid: any = await axios.put(`https://pd.${region[1]}.a.pvp.net/name-service/v2/players/`, [matchDetails.Teams[0].Players[i].Subject]).catch(function (err) {
        console.log(err.response.status);
      });
      puuid = `${puuid.data[0].GameName}#${puuid.data[0].TagLine}`;
      let playerMMR = await axiosGet(`https://pd.${region[1]}.a.pvp.net/mmr/v1/players/${matchDetails.Teams[0].Players[i].Subject}`, "JWT");
      let Rank = playerMMR.QueueSkills.competitive.SeasonalInfoBySeasonID[seasonID].CompetitiveTier;
      let Info = `${puuid} : ${Tiers[Rank]}`;
      arr.push(Info);
    }
    console.log(arr.join("\n"));
    res.send({ ranks: arr });
  } else if (req.body.type === "CoreGame") {
    let CoreGameID = await getCoreGameID();
    if (!CoreGameID) return (res.statusCode = 404), res.send({ error: "Match not found" });
    let matchDetails = await axiosGet(`https://glz-${region[0]}-1.${region[1]}.a.pvp.net/core-game/v1/matches/${CoreGameID}`, "JWT");
    let matchPlayers = matchDetails.Players;
    let arr = [];
    for (let i = 0; i < matchPlayers.length; i++) {
      let puuid: any = await axios.put(`https://pd.${region[1]}.a.pvp.net/name-service/v2/players/`, [matchDetails.Players[i].Subject]);
      let playerMMR = await axiosGet(`https://pd.${region[1]}.a.pvp.net/mmr/v1/players/${matchDetails.Players[i].Subject}`, "JWT");
      if (playerMMR.QueueSkills.competitive.SeasonalInfoBySeasonID !== null) {
        var Rank = playerMMR.QueueSkills.competitive.SeasonalInfoBySeasonID[seasonID].CompetitiveTier;
      } else Rank = 0;
      let Info = `${puuid.data[0].GameName}#${puuid.data[0].TagLine} : ${Tiers[Rank]} : ${invAgents[matchPlayers[i].CharacterID]}`;
      arr.push(Info);
    }
    console.log(arr.join("\n"));
    res.send({ ranks: arr });
  }
});
let contracts = await axios.get("https://valorant-api.com/v1/contracts");
let contractToID = {};
for (let i = 0; i < contracts.data.data.length; i++) {
  contractToID[contracts.data.data[i].displayName.split(" ")[0].toLowerCase()] = contracts.data.data[i].uuid;
}
app.post("/api/contracts/select", async (req, res) => {
  authPost(`https://pd.${region[1]}.a.pvp.net/contracts/v1/contracts/${entitlements.subject}/special/${contractToID[req.body.CharacterID]}`).catch(function (err) {
    console.log(err.response.status);
  });
  res.send({ status: 200 });
});
//TODO add contract progress

function sendHTML(fName: any, res: any) {
  fs.readFile(`./src/${fName}.html`, "utf8", (err, data) => {
    res.send(data);
  });
}
app.get("/", auth, (req, res) => {
  sendHTML("index", res);
});
app.get("/party", auth, (req, res) => {
  sendHTML("party", res);
});
app.get("/party/gamemodes", auth, (req, res) => {
  sendHTML("gamemodes", res);
});
app.get("/pregame", auth, (req, res) => {
  sendHTML("pregame", res);
});
app.get("/coregame", auth, (req, res) => {
  sendHTML("coregame", res);
});
app.get("/contracts", auth, (req, res) => {
  sendHTML("contracts", res);
});
app.get("/store", auth, (req, res) => {
  sendHTML("store", res);
});
app.get("/offline", auth, (req, res) => {
  res.send("offline");
});
app.use((req, res, next) => {
  res.status(404).send("404, Tonto");
});
let orange = chalk.hex("#FFA500");
if (process.env.PORT === "443") {
  const httpsServer = https.createServer(
    {
      key: fs.readFileSync("./ssl/privkey.pem"),
      cert: fs.readFileSync("./ssl/fullchain.pem")
    },
    app
  );
  httpsServer.listen(process.env.PORT, () => {
    console.log(`HTTPS server listening on port ${orange(process.env.PORT)}`);
  });
} else
  app.listen(process.env.PORT, () => {
    console.log(`HTTP server listening on port ${orange(80)}`);
  });
//
