const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { Web3 } = require('web3');
const { CookieJar } = require('tough-cookie');
const { wrapper } = require('axios-cookiejar-support');
const { promisify } = require('util');
const readFileAsync = promisify(fs.readFile);

const RPC_URL = 'https://rpc.gpu.net/';
const BASE_URL = 'https://token.gpu.net';
const AUTH_API_URL = 'https://quest-api.gpu.net/api';
const PK_FILE_PATH = path.join(__dirname, 'pk.txt');
const COOKIE_FILE_PATH = path.join(__dirname, 'gpu_net_cookies.json');
const LOG_FILE_PATH = path.join(__dirname, 'gpu_net_log.txt');

const jar = new CookieJar();
const client = wrapper(axios.create({ 
  jar,
  withCredentials: true 
}));


const DEFAULT_HEADERS = {
  'accept': 'application/json, text/plain, */*',
  'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
  'priority': 'u=1, i',
  'sec-ch-ua': '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
  'sec-ch-ua-mobile': '?0',
  'sec-ch-ua-platform': '"Windows"',
  'sec-fetch-dest': 'empty',
  'sec-fetch-mode': 'cors',
  'sec-fetch-site': 'same-site',
  'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36'
};


const web3 = new Web3(RPC_URL);


function logToFile(message) {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] ${message}\n`;
  
  console.log(message);
  fs.appendFileSync(LOG_FILE_PATH, logEntry);
}

async function readPrivateKeys() {
  try {
    const data = await readFileAsync(PK_FILE_PATH, 'utf8');
    return data
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
  } catch (error) {
    logToFile(`Error reading private keys file: ${error.message}`);
    throw error;
  }
}


async function initializeSession() {
  try {
    logToFile('Initializing session by visiting the main page...');
    
    const response = await client.get(BASE_URL, {
      headers: {
        ...DEFAULT_HEADERS,
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1'
      }
    });
    
    logToFile(`Main page visited. Status: ${response.status}`);

    const cookies = await jar.getCookies(BASE_URL);
    logToFile(`Initial cookies received: ${cookies.length}`);
    
    return true;
  } catch (error) {
    logToFile(`Error initializing session: ${error.message}`);
    return false;
  }
}

async function saveCookies() {
  try {
    const cookieString = await jar.serialize();
    if (typeof cookieString === 'string') {
      fs.writeFileSync(COOKIE_FILE_PATH, cookieString);
      logToFile(`Cookies saved to ${COOKIE_FILE_PATH}`);
      return true;
    } else {
      logToFile('Cookie serialization returned non-string value, skipping save');
      return false;
    }
  } catch (error) {
    logToFile(`Error saving cookies: ${error.message}`);
    return false;
  }
}


async function loadCookies() {
  try {
    if (fs.existsSync(COOKIE_FILE_PATH)) {
      const cookieString = fs.readFileSync(COOKIE_FILE_PATH, 'utf8');
      await jar.deserialize(cookieString);
      const cookies = await jar.getCookies(BASE_URL);
      logToFile(`Loaded ${cookies.length} cookies from file`);
      return true;
    }
    logToFile('No cookie file found, will create a new session');
    return false;
  } catch (error) {
    logToFile(`Error loading cookies: ${error.message}`);
    return false;
  }
}

async function getNonce(address) {
  try {
    logToFile('Getting nonce...');
    
    let url = `${AUTH_API_URL}/auth/eth/nonce`;
    if (address) {
      url += `?address=${address}`;
    }
    
    const response = await client.get(url, {
      headers: DEFAULT_HEADERS,
      referrer: BASE_URL,
      referrerPolicy: 'strict-origin-when-cross-origin'
    });
    
    logToFile(`Full nonce response: ${JSON.stringify(response.data)}`);
    
    try {
      await saveCookies();
    } catch (e) {
      logToFile('Error saving cookies after nonce, continuing anyway');
    }
    
    return response.data;
  } catch (error) {
    logToFile(`Error getting nonce: ${error.message}`);
    if (error.response) {
      logToFile(`Response status: ${error.response.status}`);
      logToFile(`Response data: ${JSON.stringify(error.response.data)}`);
    }
    throw error;
  }
}

async function signMessage(privateKey, nonceData) {
  try {
    const account = web3.eth.accounts.privateKeyToAccount(privateKey);
    const address = account.address;

    const nonce = typeof nonceData === 'string' ? nonceData : 
                 (nonceData?.nonce || nonceData?.data?.nonce || 'unknown-nonce');
    const message = `token.gpu.net wants you to sign in with your Ethereum account:\n${address}\n\nSign in with Ethereum to the app.\n\nURI: https://token.gpu.net\nVersion: 1\nChain ID: 4048\nNonce: ${nonce}\nIssued At: ${new Date().toISOString()}`;
    const signResult = account.sign(message);
    
    return {
      message,
      signature: signResult.signature,
      address
    };
  } catch (error) {
    logToFile(`Error signing message: ${error.message}`);
    throw error;
  }
}


async function verifySignature(signData) {
  try {
    logToFile('Sending verify request...');
    
    const response = await client.post(
      `${AUTH_API_URL}/auth/eth/verify`,
      {
        message: signData.message,
        signature: signData.signature
      },
      {
        headers: {
          ...DEFAULT_HEADERS,
          'content-type': 'application/json'
        },
        referrer: BASE_URL,
        referrerPolicy: 'strict-origin-when-cross-origin'
      }
    );
    
    try {
      await saveCookies();
    } catch (e) {
      logToFile('Error saving cookies after verify, continuing anyway');
    }
    
    return response.data;
  } catch (error) {
    logToFile(`Error verifying signature: ${error.message}`);
    if (error.response) {
      logToFile(`Response status: ${error.response.status}`);
      logToFile(`Response data: ${JSON.stringify(error.response.data)}`);
      if (error.response.status === 500 && error.response.data) {
        logToFile('Got a 500 error but returning available data');
        return { error: error.response.data, status: error.response.status };
      }
    }
    throw error;
  }
}

async function getUserProfile() {
  try {
    logToFile('Getting user profile...');
    
    const response = await client.get(`${AUTH_API_URL}/users/me`, {
      headers: DEFAULT_HEADERS,
      referrer: BASE_URL,
      referrerPolicy: 'strict-origin-when-cross-origin'
    });
    
    const data = response.data;
    logToFile(`User Profile - ID: ${data.id}, Current Streak: ${data.currentStreak}, Rank: ${data.rank}, Twitter Connected: ${data.isTwitterConnected}`);
    
    return data;
  } catch (error) {
    logToFile(`Error getting user profile: ${error.message}`);
    if (error.response) {
      logToFile(`Response status: ${error.response.status}`);
      logToFile(`Response data: ${JSON.stringify(error.response.data)}`);
    }
    return null;
  }
}

async function updateStreak() {
  try {
    logToFile('Updating streak...');
    
    const response = await client.post(`${AUTH_API_URL}/users/streak`, {}, {
      headers: DEFAULT_HEADERS,
      referrer: BASE_URL,
      referrerPolicy: 'strict-origin-when-cross-origin'
    });
    
    const data = response.data;
    logToFile(`Streak Update - Current Streak: ${data.streak}, Longest Streak: ${data.longestStreak}`);
    
    return data;
  } catch (error) {
    logToFile(`Error updating streak: ${error.message}`);
    if (error.response) {
      logToFile(`Response status: ${error.response.status}`);
      logToFile(`Response data: ${JSON.stringify(error.response.data)}`);
    }
    return null;
  }
}


async function getUserExperience() {
  try {
    logToFile('Getting user experience...');
    
    const response = await client.get(`${AUTH_API_URL}/users/exp`, {
      headers: DEFAULT_HEADERS,
      referrer: BASE_URL,
      referrerPolicy: 'strict-origin-when-cross-origin'
    });
    
    logToFile(`User Experience Data: ${JSON.stringify(response.data)}`);
    
    return response.data;
  } catch (error) {
    logToFile(`Error getting user experience: ${error.message}`);
    if (error.response) {
      logToFile(`Response status: ${error.response.status}`);
      logToFile(`Response data: ${JSON.stringify(error.response.data)}`);
    }
    return null;
  }
}

async function processAccount(privateKey, index) {
  try {
    logToFile(`\n[${index + 1}] Processing account with private key: ${privateKey.substring(0, 6)}...${privateKey.substring(privateKey.length - 4)}`);

    const account = web3.eth.accounts.privateKeyToAccount(privateKey);
    logToFile(`Wallet address: ${account.address}`);
    
    const nonceData = await getNonce(account.address);
    logToFile('Signing message...');
    const signData = await signMessage(privateKey, nonceData);
    logToFile('Message signed successfully');
    logToFile('Verifying signature...');

    const authResult = await verifySignature(signData);
    logToFile(`Authentication result: ${JSON.stringify(authResult)}`);
    
    if (authResult.error) {
      logToFile(`Authentication failed for account ${index + 1}`);
      return { success: false, address: account.address };
    }

    const profileData = await getUserProfile();
    const streakData = await updateStreak();
    const expData = await getUserExperience();
    
    return { 
      success: true, 
      address: account.address,
      profile: profileData,
      streak: streakData,
      exp: expData
    };
  } catch (error) {
    logToFile(`Processing failed for account ${index + 1}: ${error.message}`);
    return { success: false, error: error.message };
  }
}


async function processAllAccounts() {
  try {
    logToFile('\n===== STARTING NEW PROCESSING CYCLE =====');
    logToFile(`Time: ${new Date().toLocaleString()}`);
    
    await loadCookies();
    await initializeSession();

    const privateKeys = await readPrivateKeys();
    logToFile(`Found ${privateKeys.length} private keys in the file`);
    
    const results = [];
    for (let i = 0; i < privateKeys.length; i++) {
      const result = await processAccount(privateKeys[i], i);
      results.push(result);
      
      if (i < privateKeys.length - 1) {
        const delayTime = 5000 + Math.random() * 5000;
        logToFile(`Waiting ${Math.round(delayTime/1000)} seconds before next account...`);
        await new Promise(resolve => setTimeout(resolve, delayTime));
      }
    }
    
    logToFile('\n===== PROCESSING CYCLE SUMMARY =====');
    logToFile(`Total accounts processed: ${results.length}`);
    logToFile(`Successful authentications: ${results.filter(r => r.success).length}`);
    logToFile(`Failed authentications: ${results.filter(r => !r.success).length}`);
    
    return true;
  } catch (error) {
    logToFile(`Error in processing cycle: ${error.message}`);
    return false;
  }
}


async function main() {
  try {
    logToFile('Starting GPU.NET script with 24-hour loop...');
    
    while (true) {
      await processAllAccounts();
      
      const nextRunTime = new Date(Date.now() + 24 * 60 * 60 * 1000);
      logToFile(`\nCompleted cycle. Next run scheduled at: ${nextRunTime.toLocaleString()}`);
      logToFile('Waiting 24 hours before next run...');
      
      await new Promise(resolve => setTimeout(resolve, 24 * 60 * 60 * 1000));
    }
  } catch (error) {
    logToFile(`Fatal error in main process: ${error.message}`);
    process.exit(1);
  }
}


main();