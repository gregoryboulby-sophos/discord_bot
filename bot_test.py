import discord
import re
import time
import hashlib
import requests
import json
import base64

#Some globals.
client = discord.Client()
cfg = None
auth_credentials = {
                    'token': None,
                    'timestamp':3601 
                   }


def read_config():
    with open('config.json') as f:
        cfg = json.load(f)        
    return cfg    
    
def get_file(url):
    return requests.get(url=url)
    
def gen_sha256(url):
       response = get_file(url)
       sha256_hash = hashlib.sha256()
       for chunk in response.iter_content(chunk_size= 1024):
            sha256_hash.update(chunk)
       return sha256_hash.hexdigest()

def token_valid(credentials):
    current_time = int(time.time())
    time_diff = current_time - credentials['timestamp']
    return time_diff < 3600

def intelix_file_lookup(sha256):
    # Add token stuff
    if not token_valid(auth_credentials):
        print("Updating creds.")
        intelix_get_token(cfg) 
    else:
        print("Creds up to date.")
   
    file_url = "https://de.api.labs.sophos.com/lookup/files/v1/%s" % (sha256)
    return requests.get(url=file_url, headers = {"Authorization": auth_credentials['token'],"X-Correlation-ID": "MyUniqueId"})


def intelix_url_lookup(url):
    # Add token stuff
    if not token_valid(auth_credentials):
        print("Updating creds.")
        intelix_get_token(cfg) 
    else:
        print("Creds up to date.") 

    file_url = "https://de.api.labs.sophos.com/lookup/urls/v1/%s" % (url)
    return requests.get(url=file_url, headers = {"Authorization": auth_credentials['token'],"X-Correlation-ID": "MyUniqueId"})


def intelix_get_token(cfg):
    global auth_credentials
    auth = base64.b64encode(bytes('%s:%s' %  (cfg['client_id'],cfg['client_secret']),'utf-8'))
 
    token_url = 'https://api.labs.sophos.com/oauth2/token'
    header = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': 'Basic %s' % (auth.decode('utf-8'))}
    data = {'grant_type':'client_credentials'}
    response = requests.post(url=token_url,headers=header,data = data)
    response_json = json.loads(response.content.decode('utf-8'))
    print("response received :" + str(response_json))
    auth_credentials =  {'token': response_json['access_token'],
                         'timestamp': int(time.time())
                        }


@client.event
async def on_message(message):
    # we do not want the bot to reply to itself
    if message.author == client.user:
        return

    if message.content.startswith('Who the best anti-virus vendor'):
        msg = 'Hello {0.author.mention}'.format(message)
        await message.channel.send('Mcafee') 

    if message.attachments:
       url = message.attachments[0].url
       sha256 = gen_sha256(url)
       file_response = intelix_file_lookup(sha256)
       await message.channel.send(file_response.content)

    urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',message.content.lower())
    
    if urls:
        if urls[0].startswith('https'):
           url = urls[0][8:]
        elif urls[0].startswith('http'):
           url = urls[0][7:]
        url_response = intelix_url_lookup(url)
        await message.channel.send(url_response.content)
        

@client.event
async def on_ready():
    print('Logged in as')
    print(client.user.name)
    print(client.user.id)
    print('------')

def main():
    global cfg
    global auth_credentials

    cfg = read_config()
    #auth = base64.b64encode(bytes('%s:%s' % (cfg['client_id'],cfg['client_secret']),'utf-8')) 
    #access_response = intelix_get_token()
    #auth_credentials =  {'token': access_response['access_token'], 
    #			 'timestamp': int(time.time())
    #	}   
     
    client.run(cfg['bot_token'])

if __name__ == '__main__':
    main()
