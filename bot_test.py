import discord
import re
import time
import hashlib
import requests
import json
import base64
from urllib.parse import urlparse

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
    
def gen_sha256(response):
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

def intelix_submit_static(file_content):
    # Add token stuff
    if not token_valid(auth_credentials):
        print("Updating creds.")
        intelix_get_token(cfg) 
    else:
        print("Creds up to date.") 

    url = "https://de.api.labs.sophos.com/analysis/file/static/v1"
    headers = {"Authorization": auth_credentials['token'],"X-Correlation-ID": "MyUniqueId"}
    data = {'file': file_content}
    return requests.post(url=url, headers=headers, files=data)

def get_static_report(job_id):
    # Add token stuff
    if not token_valid(auth_credentials):
        print("Updating creds.")
        intelix_get_token(cfg) 
    else:
        print("Creds up to date.") 

    url = "https://de.api.labs.sophos.com/analysis/file/static/v1/reports/{}".format(job_id)
    headers = {"Authorization": auth_credentials['token'],"X-Correlation-ID": "MyUniqueId"}
    return requests.get(url=url, headers=headers)


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
def get_jobID(response):
    response_json = json.loads(response.decode('utf-8'))
    return response_json['jobId']

def wait_for_analysis(job_id, scan_type='static'):
    if scan_type == 'static':
        while True:
            report_response = get_static_report(job_id)
            if report_response.status_code == 200:
                return report_response
            elif report_response.status_code == 202:
                print('Job still in progress sleeping for 5 seconds...')
                time.sleep(5)
            else:
                print('Something went wrong with the request')
                break

def get_static_score(static_response):
    result = json.loads(static_response.content.decode('utf-8'))
    return result['report']['score']

def handle_scanning(file_content, scan_type='static'):
    if scan_type == 'static':
        submit_response = intelix_submit_static(file_content)
        if submit_response.status_code == 200:
            print('Static analysis complete returning results...')
            return get_static_score(submit_response)
        elif submit_response.status_code == 202:
            print('Static analysis in progress waiting...')
            job_id = get_jobID(submit_response.content)
            static_result = wait_for_analysis(job_id)
            return get_static_score(static_result)
        elif submite_response.status == '413':
            print('Request too large ignoring')
        else:
            print ('Problem with request {} Content: {}'.format(submit_response.status_code, submit_response.content))

def get_domain(url):
   parsed_url = urlparse(url)
   return parsed_url.netloc

def parse_file_lookup(lookup_response):
    lookup = json.loads(lookup_response.decode('utf-8'))
    try:
        score = int(lookup['reputationScore'])
        if score < 20:
            risk = 'MALWARE'
        elif score < 30:
            risk = 'PUA'
        elif score < 70:
            risk = 'UNKNOWN'
        else:
            risk = 'GOOD'
    except KeyError:
        risk = 'UNKNOWN'
    return risk

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
        file_response = get_file(url)
        sha256 = gen_sha256(file_response)
        file_lookup_response = intelix_file_lookup(sha256)
        file_risk = parse_file_lookup(file_lookup_response.content)
        await message.channel.send(file_risk)
        if file_risk == 'UNKNOWN':
            await message.channel.send('We cor figure out what you uploaded. We are gooin to scan it.')
            score = handle_scanning(file_response.content, scan_type='static')
            if score < 50:
                await message.channel.send('It looks like this file is bad so I have to delete it. I wish someone would delete me.')
                await message.delete(delay=5)
            else:
                print('File looks non malicious')
        elif file_risk == 'MALWARE':
            print('File is malware deleting')
            await message.delete(delay=5)
        elif file.risk == 'PUA':
            await message.channel.send("File is a potentially unwanted application and may be malicious. Proceed with caution or don't its up to you yo")

    urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',message.content.lower())
    
    if urls:
        url = get_domain(urls[0])
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
