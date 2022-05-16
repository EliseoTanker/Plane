let dev = false;
import * as dotenv from "dotenv";
dotenv.config();
import express from "express";
const app = express();
import ip from "ip";
import axios from "axios";
import chalk from "chalk";
import * as https from "https";
import * as fs from "fs";
import * as crypto from "crypto";
import * as path from "path";
import Auth from "basic-auth";
import rateLimit from "express-rate-limit";
import { credentialsAuth, lockfileAuth, agent } from "./val-auth.js";
function file_hash() {
  const fileBuffer = fs.readFileSync(
    path.basename(new URL("", import.meta.url).pathname)
  );
  const hashSum = crypto.createHash("md5");
  hashSum.update(fileBuffer);
  const hex = hashSum.digest("hex");
  return hex;
}
async function check_version() {
  let hash = await file_hash();
  let github_hash = (
    await axios.get(
      "https://raw.githubusercontent.com/EliseoTanker/PWA-Typescript/main/file-hash-thing.json"
    )
  ).data.hash;
  if (github_hash !== hash) {
    console.log(
      chalk.red(
        `Your version of the application appears to be outdated (Current MD5 hash ${hash}, expected hash ${github_hash})`
      )
    );
  }
}
if (!dev) await check_version();
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: true,
});
const auth = function (res, req, next) {
  var user = Auth(res);
  if (
    !user ||
    process.env.AUTH_USERNAME !== user.name ||
    process.env.AUTH_PASSWORD !== user.pass
  ) {
    req.set("WWW-Authenticate", 'Basic realm="example"');
    return req.status(401).send();
  }
  return next();
};
const invAgents: any = {
  "": "In Range",
  "41fb69c1-4189-7b37-f117-bcaf1e96f1bf": "Astra",
  "5f8d3a7f-467b-97f3-062c-13acf203c006": "Breach",
  "22697a3d-45bf-8dd7-4fec-84a9e28c69d7": "Chamber",
  "117ed9e3-49f3-6512-3ccf-0cada7e3823b": "Cypher",
  "601dbbe7-43ce-be57-2a40-4abd24953621": "Kay/o",
  "1e58de9c-4950-5125-93e9-a0aee9f98746": "Killjoy",
  "bb2a4828-46eb-8cd1-e765-15848195d751": "Neon",
  "f94c3b30-42be-e959-889c-5aa313dba261": "Raze",
  "6f2a04ca-43e0-be17-7f36-b3908627744d": "Skye",
  "707eab51-4836-f488-046a-cda6bf494859": "Viper",
  "7f94d92c-4234-0a36-9646-3a87eb8b5c89": "Yoru",
  "9f0d8ba9-4140-b941-57d3-a7ad57c6b417": "Brimstone",
  "add6443a-41bd-e414-f6ad-e58d267f4e95": "Jett",
  "8e253930-4c05-31dd-1b6c-968525494517": "Omen",
  "eb93336a-449b-9c1b-0a54-a891f7921d69": "Phoenix",
  "a3bfb853-43b2-7238-a4f1-ad90e9e46bcc": "Reyna",
  "569fdd95-4d10-43ab-ca70-79becc718b46": "Sage",
  "320b2a48-4d9b-a075-30f1-1f93a9b638fa": "Sova",
  "dade69b4-4f5a-8528-247b-219e5a1facd6": "Fade",
};
const agents = {
  astra: "41fb69c1-4189-7b37-f117-bcaf1e96f1bf",
  breach: "5f8d3a7f-467b-97f3-062c-13acf203c006",
  brimstone: "9f0d8ba9-4140-b941-57d3-a7ad57c6b417",
  chamber: "22697a3d-45bf-8dd7-4fec-84a9e28c69d7",
  cypher: "117ed9e3-49f3-6512-3ccf-0cada7e3823b",
  jett: "add6443a-41bd-e414-f6ad-e58d267f4e95",
  "kay/o": "601dbbe7-43ce-be57-2a40-4abd24953621",
  killjoy: "1e58de9c-4950-5125-93e9-a0aee9f98746",
  neon: "bb2a4828-46eb-8cd1-e765-15848195d751",
  omen: "8e253930-4c05-31dd-1b6c-968525494517",
  phoenix: "eb93336a-449b-9c1b-0a54-a891f7921d69",
  raze: "f94c3b30-42be-e959-889c-5aa313dba261",
  reyna: "a3bfb853-43b2-7238-a4f1-ad90e9e46bcc",
  sage: "569fdd95-4d10-43ab-ca70-79becc718b46",
  skye: "6f2a04ca-43e0-be17-7f36-b3908627744d",
  sova: "320b2a48-4d9b-a075-30f1-1f93a9b638fa",
  viper: "707eab51-4836-f488-046a-cda6bf494859",
  yoru: "7f94d92c-4234-0a36-9646-3a87eb8b5c89",
  fade: "dade69b4-4f5a-8528-247b-219e5a1facd6",
};
async function heartbeat() {
  await axios.post(
    "https://betteruptime.com/api/v1/heartbeat/sVMghGFnCpApCcq9NZTAQLpt"
  );
}
setTimeout(heartbeat, 15000);
heartbeat();
process.on("uncaughtException", function (err) {
  //console.log(err);
});
app
  .use(limiter)
  .use(express.static("public"))
  .use(express.json())
  .use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", ip.address());
    res.header(
      "Access-Control-Allow-Headers",
      "Origin, X-Requested-With, Content-Type, Accept"
    );
    next();
  });
async function axiosGet(url: string, headers: any, entitlements: any) {
  if (headers === "JWT") {
    var res = await axios.get(url, {
      headers: {
        "X-Riot-Entitlements-JWT": entitlements.token,
        "X-Riot-ClientVersion": await getVersion(),
        "X-Riot-ClientPlatform":
          "ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9TVmVyc2lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIlVua25vd24iDQp9",
        Authorization: "Bearer " + entitlements.access_token,
      },
      httpsAgent: new https.Agent({
        rejectUnauthorized: false,
      }),
    });
  } else {
    var res = await axios.get(url, {
      headers: headers,
      httpsAgent: new https.Agent({
        rejectUnauthorized: false,
      }),
    });
  }
  return res.data;
}
async function authPost(
  url: string,
  entitlements: any,
  body?: any,
  method?: any
) {
  if (!body) {
    var body: any = {};
  }
  if (!method) {
    var method: any = "post";
  }
  let config = {
    headers: {
      "X-Riot-Entitlements-JWT": entitlements.token,
      Authorization: "Bearer " + entitlements.access_token,
      "X-Riot-ClientVersion": await getVersion(),
      "X-Riot-ClientPlatform":
        "ew0KCSJwbGF0Zm9ybVR5cGUiOiAiUEMiLA0KCSJwbGF0Zm9ybU9TIjogIldpbmRvd3MiLA0KCSJwbGF0Zm9ybU9TVmVyc2lvbiI6ICIxMC4wLjE5MDQyLjEuMjU2LjY0Yml0IiwNCgkicGxhdGZvcm1DaGlwc2V0IjogIlVua25vd24iDQp9",
    },
  };
  method === "delete"
    ? axios.delete(url, config)
    : axios[method](url, body, config);
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
import readlineSync from "readline-sync";
let region: any = ["na", "na"];
if (process.env.AUTH_MODE === "Credentials") {
  if (dev) {
    var entitlements: Entitlements = await credentialsAuth(
      process.env.VAL_USERNAME,
      process.env.VAL_PASSWORD
    );
  } else {
    let username = readlineSync.question("Riot username: ");
    let password = readlineSync.question("Password: ", {
      hideEchoBack: true,
    });
    var entitlements: Entitlements = await credentialsAuth(username, password);
  }
  var regions = (
    await axios.put(
      "https://riot-geo.pas.si.riotgames.com/pas/v1/product/valorant",
      { id_token: entitlements.id_token },
      {
        headers: {
          Authorization: `Bearer ${entitlements.access_token}`,
        },
        httpsAgent: agent,
      }
    )
  ).data.affinities;
  region = [regions.live, regions.pbe];
} else if (process.env.AUTH_MODE === "Lockfile") {
  var entitlements: Entitlements = await lockfileAuth();
  if (dev) {
    region = process.env.REGIONS.split(" ");
  } else {
    region = readlineSync.question(
      "Region (Twice, separated by a space. E.g.: na na, if region = br/latam set shard first then na): "
    );
  }
} else console.log('Invalid auth type (Must be "Lockfile" or "Credentials"');

async function getVersion() {
  let version = (await axios.get("https://valorant-api.com/v1/version")).data
    .data.riotClientVersion;
  return version;
}
async function getPreGameID(entitlements: any) {
  let preGameMatchID = await axiosGet(
    `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/pregame/v1/players/${entitlements.subject}`,
    "JWT",
    entitlements
  ).catch(function () {
    console.log("Pregame match not found");
    return;
  });
  return preGameMatchID.MatchID;
}
async function getCoreGameID(entitlements: any) {
  let CoreGameMatchID = await axiosGet(
    `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/core-game/v1/players/${entitlements.subject}`,
    "JWT",
    entitlements
  ).catch(function () {
    console.log("Match not found");
    return;
  });
  if (CoreGameMatchID !== undefined) {
    return CoreGameMatchID.MatchID;
  }
}
app.post("/api/party/gamemode", async (req, res) => {
  let partyReq = await axiosGet(
    `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/players/${entitlements.subject}`,
    "JWT",
    entitlements
  ).catch(function (err) {
    console.log(`Party request returned an error`);
  });
  await authPost(
    `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/parties/${partyReq.CurrentPartyID}/queue/`,
    entitlements,
    {
      queueID: req.body.id,
    }
  ).catch((err) => {
    if (err) {
      if (err.response.data.httpStatus === 400) {
        res.statusCode = 400;
        let message = "Can't change gamemode while in custom game";
        res.send({ error: message });
        console.log(message);
      } else {
        let message = "Gamemode not avaliable";
        res.send({ error: message });
        console.log(message);
      }
    } else {
      res.send({ gamemode: req.body.id });
      console.log(`Gamemode selected: ${req.body.id}`);
    }
  });
});
app.post("/api/party/ready", async (req, res) => {
  let partyReq = await axiosGet(
    `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/players/${entitlements.subject}`,
    "JWT",
    entitlements
  );
  if (req.body.ready === true) var ready = true;
  if (req.body.ready === false) var ready = false;
  await authPost(
    `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/parties/${partyReq.CurrentPartyID}/members/${entitlements.subject}/setReady`,
    entitlements,
    {
      ready: ready,
    }
  );
});
app.post("/api/party/a11y", async (req, res) => {
  let partyReq = await axiosGet(
    `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/players/${entitlements.subject}`,
    "JWT",
    entitlements
  );
  if (req.body.status === true) var a11y = "CLOSED";
  if (req.body.status === false) var a11y = "OPEN";
  await authPost(
    `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/parties/${partyReq.CurrentPartyID}/accessibility`,
    entitlements,
    {
      accessibility: a11y,
    }
  );
});
app.post("/api/party/queue", async (req, res) => {
  let partyReq = await axiosGet(
    `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/players/${entitlements.subject}`,
    "JWT",
    entitlements
  );
  authPost(
    `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/parties/${
      partyReq.CurrentPartyID
    }/${req.body.type === "Custom" ? "startcustomgame" : "matchmaking/join"}`,
    entitlements
  ).catch(function (err) {
    console.log(err.response.data);
  });
  console.log(
    req.body.type === "Custom" ? "Started custom game" : "Joined matchmaking"
  );
});
app.post("/api/party/leave-queue", async (req, res) => {
  let partyReq = await axiosGet(
    `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/players/${entitlements.subject}`,
    "JWT",
    entitlements
  ).catch(function () {
    console.log(`Party request returned an error`);
  });
  await authPost(
    `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/parties/${partyReq.CurrentPartyID}/matchmaking/leave/`,
    entitlements
  ).catch(function (err) {
    console.log(err.response.data);
  });
  res.send({ success: true });
  console.log("Left matchmaking");
});
app.post("/api/select", async (req, res) => {
  let PreGameID = await getPreGameID(entitlements);
  if (!PreGameID)
    return (res.statusCode = 404), res.send({ error: "Match not found" });
  let pröAgent = agents[invAgents[req.body.agentID].toLowerCase()];
  await authPost(
    `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/pregame/v1/matches/${PreGameID}/select/${pröAgent}`,
    entitlements
  ).catch(function (err) {
    console.log(err.response.data);
  });
  console.log(`Selected Agent: ${invAgents[req.body.agentID]}`);
  res.send({
    succes: true,
    agent: invAgents[req.body.agentID],
  });
});
app.post("/api/lock", async (req, res) => {
  let PreGameID = await getPreGameID(entitlements);
  if (!PreGameID)
    return (res.statusCode = 404), res.send({ error: "Match not found" });
  let MatchDetails = await axiosGet(
    `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/pregame/v1/matches/${PreGameID}`,
    "JWT",
    entitlements
  );
  let MatchPlayers = MatchDetails.Teams[0].Players;
  for (let i = 0; i < MatchPlayers.length; i++) {
    let matchSubject = MatchPlayers[i].Subject;
    if (matchSubject === entitlements.subject) {
      if (MatchDetails.Teams[0].Players[i].CharacterID == "")
        console.log("No agent selected");
      else {
        let selectedAgent = MatchDetails.Teams[0].Players[i].CharacterID;
        authPost(
          `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/pregame/v1/matches/${PreGameID}/lock/${selectedAgent}`,
          entitlements
        ).catch(function (err) {
          console.log(
            `${err.response.data.httpStatus} ${err.response.data.message}`
          );
        });
        res.send({ succes: true, agentSelected: invAgents[selectedAgent] });
      }
    }
  }
});
let Skins = {
  Vandal: "9c82e19d-4575-0200-1a81-3eacf00cf872",
  Classic: "29a0cfab-485b-f5d5-779a-b59f85e204a8",
};
app.post("/api/loadouts", async (req, res) => {
  if (req.body.type === "PreGame") {
    res.send({ implemented: false });
  } else if (req.body.type === "CoreGame") {
    let CoreGameID = await getCoreGameID(entitlements);
    if (!CoreGameID)
      return (res.statusCode = 404), res.send({ error: "Match not found" });
    let matchDetails = await axiosGet(
      `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/core-game/v1/matches/${CoreGameID}`,
      "JWT",
      entitlements
    ).catch(function (err) {
      if (err.response.status === 404) {
        console.log("Error: Match not found");
      }
    });
    let matchPlayers = matchDetails.Players;
    let arr = [];
    for (let i = 0; i < matchPlayers.length; i++) {
      //Player
      let name: any = await axios
        .put(`https://pd.${region[1]}.a.pvp.net/name-service/v2/players/`, [
          matchPlayers[i].Subject,
        ])
        .catch(function (err) {
          console.log(err.response.status);
        });
      name = `${name.data[0].GameName}#${name.data[0].TagLine}`;
      let agent = invAgents[matchPlayers[i].CharacterID];
      //Skin
      let loadout = await axiosGet(
        `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/core-game/v1/matches/${CoreGameID}/loadouts`,
        "JWT",
        entitlements
      );
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
      let Skin =
        loadout.Loadouts[i].Loadout.Items[Skins["Vandal"]].Sockets[
          "bcef87d6-209b-46c6-8b19-fbe40bd95abc"
        ].Item.ID;
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
    res.send({ skins: arr });
    console.log(arr);
  }
});
app.post("/api/exit", async (req, res) => {
  if (req.body.type === "PreGame") {
    let PreGameID = await getPreGameID(entitlements);
    if (!PreGameID)
      return (res.statusCode = 404), res.send({ error: "Match not found" });
    await authPost(
      `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/pregame/v1/matches/${PreGameID}/quit`,
      entitlements
    ).catch((err) => {
      console.log(err.response.data);
    });
  } else if (req.body.type === "CoreGame") {
    let coreGameID = await getCoreGameID(entitlements);
    if (!coreGameID)
      return (res.statusCode = 404), res.send({ error: "Match not found" });
    await authPost(
      `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/core-game/v1/players/${entitlements.subject}/disassociate/${coreGameID}`,
      entitlements
    ).catch((err) => {
      console.log(err.response.data);
    });
  } else if (req.body.type === "Party") {
    await authPost(
      `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/parties/v1/players/${entitlements.subject}`,
      entitlements,
      {},
      "delete"
    ).catch((err) => {
      console.log(err.response.data);
    });
    res.send({ status: 200 });
  }
});
app.post("/api/store", async (req, res) => {
  let SkinOffers = (
    await axiosGet(
      `https://pd.${region[1]}.a.pvp.net/store/v2/storefront/${entitlements.subject}`,
      "JWT",
      entitlements
    )
  ).SkinsPanelLayout.SingleItemOffers;
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
  24: "Radiant",
};
app.post("/api/ranks", async (req, res) => {
  let seasonID = "3e47230a-463c-a301-eb7d-67bb60357d4f";
  if (req.body.type === "PreGame") {
    let PreGameID = await getPreGameID(entitlements);
    if (!PreGameID)
      return (res.statusCode = 404), res.send({ error: "Match not found" });
    let matchDetails = await axiosGet(
      `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/pregame/v1/matches/${PreGameID}`,
      "JWT",
      entitlements
    );
    let matchPlayers = matchDetails.Teams[0].Players;
    let arr = [];
    for (let i = 0; i < matchPlayers.length; i++) {
      let puuid: any = await axios
        .put(`https://pd.${region[1]}.a.pvp.net/name-service/v2/players/`, [
          matchDetails.Teams[0].Players[i].Subject,
        ])
        .catch(function (err) {
          console.log(err.response.status);
        });
      puuid = `${puuid.data[0].GameName}#${puuid.data[0].TagLine}`;
      let playerMMR = await axiosGet(
        `https://pd.${region[1]}.a.pvp.net/mmr/v1/players/${matchDetails.Teams[0].Players[i].Subject}`,
        "JWT",
        entitlements
      );
      let Rank =
        playerMMR.QueueSkills.competitive.SeasonalInfoBySeasonID[seasonID]
          .CompetitiveTier;
      let Info = `${puuid} : ${Tiers[Rank]}`;
      arr.push(Info);
    }
    console.log(arr.join("\n"));
    res.send({ ranks: arr });
  } else if (req.body.type === "CoreGame") {
    let CoreGameID = await getCoreGameID(entitlements);
    if (!CoreGameID)
      return (res.statusCode = 404), res.send({ error: "Match not found" });
    let matchDetails = await axiosGet(
      `https://glz-${region[0]}-1.${region[1]}.a.pvp.net/core-game/v1/matches/${CoreGameID}`,
      "JWT",
      entitlements
    );
    let matchPlayers = matchDetails.Players;
    let arr = [];
    for (let i = 0; i < matchPlayers.length; i++) {
      let puuid: any = await axios.put(
        `https://pd.${region[1]}.a.pvp.net/name-service/v2/players/`,
        [matchDetails.Players[i].Subject]
      );
      let playerMMR = await axiosGet(
        `https://pd.${region[1]}.a.pvp.net/mmr/v1/players/${matchDetails.Players[i].Subject}`,
        "JWT",
        entitlements
      );
      if (playerMMR.QueueSkills.competitive.SeasonalInfoBySeasonID !== null) {
        var Rank =
          playerMMR.QueueSkills.competitive.SeasonalInfoBySeasonID[seasonID]
            .CompetitiveTier;
      } else Rank = 0;
      let Info = `${puuid.data[0].GameName}#${puuid.data[0].TagLine} : ${
        Tiers[Rank]
      } : ${invAgents[matchPlayers[i].CharacterID]}`;
      arr.push(Info);
    }
    console.log(arr.join("\n"));
    res.send({ ranks: arr });
  }
});
//TODO
let contracts = await axios.get("https://valorant-api.com/v1/contracts");
let contractToID = {};
for (let i = 0; i < contracts.data.data.length; i++) {
  contractToID[contracts.data.data[i].displayName] =
    contracts.data.data[i].uuid;
}
app.post("/api/contracts/select", async (req, res) => {
  authPost(
    `https://pd.${region[1]}.a.pvp.net/contracts/v1/contracts/${
      entitlements.subject
    }/special/${contractToID[req.body.CharacterID]}`,
    entitlements
  );
  res.send({ status: 200 });
});

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
app.get("/test", (req, res) => {
  res.send("Hello World");
});
app.get("/r", (req, res) => {
  console.log(req.ip);
  res.redirect("https://youtu.be/dQw4w9WgXcQ");
});
let orange = chalk.hex("#FFA500");
if (dev) {
  const httpsServer = https.createServer(
    {
      key: fs.readFileSync("./ssl/privkey.pem"),
      cert: fs.readFileSync("./ssl/fullchain.pem"),
    },
    app
  );
  httpsServer.listen(process.env.PORT, () => {
    console.log(`HTTPS server listening on port ${orange(process.env.PORT)}`);
  });
} else
  app.listen(80, () => {
    console.log(`HTTP server listening on port ${orange(80)}`);
  });
