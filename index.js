import express from "express";
import axios from "axios";
import bodyParser from "body-parser";
import fs from "fs";
import { dirname } from "path";
import path from 'path';
import { fileURLToPath, URLSearchParams } from "url";// VirusTotal requirement

const port = 3000;
const app = express();
const __dirname = dirname(fileURLToPath(import.meta.url));

let API_KEY = fs.readFileSync(path.resolve(__dirname, 'API key.txt'), 'utf8'); // import API KEY from separate file

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

const API_URL = "https://www.virustotal.com/api/v3";
const auth = {
  headers: {
    accept: "application/json",
    "x-apikey":
      `${API_KEY}`,    // REPLACE API KEY WITH YOURS
    "content-type": "application/x-www-form-urlencoded",
  },
};

app.get("/", (req, res) => {
  res.render("index.ejs", {
    safety: " Choose an option below ↓",
  });
});

app.post("/send-url", async (req, res) => {
  const encodedParams = new URLSearchParams();
  encodedParams.set("url", `${req.body.url}`); // encode url in headers (VirusTotal requirement)
  try {
    const result = await axios.post(API_URL + "/urls", encodedParams, auth); // send url to VirusTotal and receive the id of analysis
    var idOfAnalysis = result.data.data.id;
  } catch (error) {
    console.log(error);
  }
  //console.log(result.data);
  try {
    const analysis = await axios.get(
      API_URL + "/analyses/" + idOfAnalysis,
      auth
    ); // get the analysis report using the id from above
    //console.log(analysis.data);
    if (
      typeof analysis.data.data.attributes.results.BitDefender !== "undefined"
    ) {
      // check if data is sent by API
      res.render("index.ejs", {
        safety: analysis.data.data.attributes.results.BitDefender.category,
        userinput: req.body.url,
      }); // render safety status from BitDefender
    } else
      res.render("index.ejs", {
        error:
          "Inexistend URL or the API has reached it's rate limit. Try again in 1 minute.",
      });
  } catch (error) {
    console.log(error);
  }
});

app.post("/send-domain", async (req, res) => {
  try {
    const result = await axios.get(
      API_URL + "/domains/" + req.body.domain,
      auth
    ); // request domain analysis
    //console.log(result.data);
    res.render("index.ejs", {
      safety:
        result.data.data.attributes.last_analysis_results.BitDefender.category,
      userinput: req.body.domain,
    });
  } catch (error) {
    if (error.response.data.error.message.includes("domain pattern")) {
      // Modify error content
      var errorDomain = `${req.body.domain} is not a valid domain name`;
    } else {
      var errorDomain = error.response.data.error.message;
    }
    res.render("index.ejs", { error: errorDomain });
    console.log(error.response.data);
  }
});

app.post("/send-ip", async (req, res) => {
  try {
    const result = await axios.get(
      API_URL + "/ip_addresses/" + req.body.ipaddress,
      auth
    );
    // console.log(result.data);
    res.render("index.ejs", {
      safety:
        result.data.data.attributes.last_analysis_results.BitDefender.category,
      userinput: req.body.ipaddress,
    });
  } catch (error) {
    if (error.response.data.error.message.includes("address pattern")) {
      var errorIP = `${req.body.ipaddress} is not a valid IP address`;
    } else {
      var errorIP = error.response.data.error.message;
    }
    res.render("index.ejs", { error: errorIP });
    console.log(error.response.data);
  }
});

app.listen(port, (req, res) => {
  console.log(`Running on port ${port}.`);
});
