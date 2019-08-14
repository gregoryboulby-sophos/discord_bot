import datetime
import discord
import re
import time
import hashlib
import requests
import json
import base64
import pickledb
from urllib.parse import urlparse

#Some globals.
########################################
client = discord.Client()
cfg = None
auth_credentials = {
                    'token': None,
                    'timestamp':3601 
                   }

db = pickledb.load('stats.db', False)
filter_list = []
#######################################

def read_config():
    with open('config.json') as f:
        cfg = json.load(f)        
    return cfg    
    

def init_stats(stats_db, force = False):
    if not stats_db.get("start_time") or force is True:
        stats_db.set("start_time", str(datetime.datetime.now()))
        stats_db.set("month", datetime.datetime.now().month)
        stats_db.set("number_of_url_lookups",1000)
        stats_db.set('number_of_file_lookups', 1000)
        stats_db.set("number_of_static_scans", 100)
        stats_db.set("number_of_dynamic_scans", 25)

        stats_db.dump()


def update_stats(stats_db, stat_type):
    if stat_type == 'url':
        stat = "number_of_url_lookups"
    elif stat_type == 'file_lookup':
        stat = 'number_of_file_lookups'
    elif stat_type == 'dynamic_scan':
        stat = 'number_of_dynamic_scans'
    else:
        stat = "number_of_static_scans"

    orig_value = stats_db.get(stat)
    new_value = orig_value + 1
    stats_db.set(stat, new_value)
    
    
    #If month changed reset counters.
    saved_month = stats_db.get("month")
    current_month = datetime.datetime.now().month
    #print("saved month is %s and current month is %s updating..." % (saved_month, current_month))
    #init_stats(stats_db, True) 
    if saved_month != current_month:
       print("saved month is %s and current month is %s updating..." % (saved_month, current_month))
       init_stats(stats_db, True) 

    stats_db.dump( )


def get_stats(stats_db):
    info =   "Number of files looked up :" + str(stats_db.get("number_of_file_lookups")) + "\n" \
           + "number_of_static_scans: " + str(stats_db.get("number_of_static_scans")) + "\n" \
           + "number_of_dynamic_scans: " + str(stats_db.get("number_of_dynamic_scans")) + "\n" \
           + "number of urls looked up :" + str(stats_db.get("number_of_url_lookups")) + "\n" \
           + "since:" + str(stats_db.get("start_time")) + "\n" \
           + "estimated cost:" + str(estimate_costs(stats_db))
    
    return info

def estimate_costs(stats_db):
    no_urls = stats_db.get("number_of_url_lookups")
    no_files_lu = stats_db.get('number_of_file_lookups')
    no_files_sc = stats_db.get("number_of_static_scans")
    no_dynamic = stats_db.get("number_of_dynamic_scans")

    url_cost =       0 if no_urls <= 1000  else (no_urls - 1000)*0.002
    files_lu_cost =  0 if no_files_lu <= 1000  else (no_files_lu - 1000)*0.002
    files_sc__cost = 0 if no_files_sc <= 100   else (no_files_sc - 100)*0.02
    files_dn_cost = 0 if no_dynamic <= 100   else (no_dynamic - 25)*0.4

    total_cost = url_cost + files_lu_cost + files_sc__cost + files_dn_cost
   
    return total_cost

def get_filter_list(category_level='off'):
    filters = cfg['filters']
    if category_level == 'low':
        filter_list = filters['low']
    elif category_level == 'medium':
        filter_list = filters['low'] + filters['medium']
    elif category_level == 'high':
        filter_list = filters['low'] + filters['medium'] + filters['high']
    elif category_level == 'off':
        filter_list = []
    return filter_list
    


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

def intelix_submit_dynamic(file_content):
    # Add token stuff
    if not token_valid(auth_credentials):
        print("Updating creds.")
        intelix_get_token(cfg) 
    else:
        print("Creds up to date.") 

    url = "https://de.api.labs.sophos.com/analysis/file/dynamic/v1"
    headers = {"Authorization": auth_credentials['token'],"X-Correlation-ID": "MyUniqueId"}
    data = {'file': file_content}
    return requests.post(url=url, headers=headers, files=data)

def get_dynamic_report(job_id):
    # Add token stuff
    if not token_valid(auth_credentials):
        print("Updating creds.")
        intelix_get_token(cfg) 
    else:
        print("Creds up to date.") 

    url = "https://de.api.labs.sophos.com/analysis/file/dynamic/v1/reports/{}".format(job_id)
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

    elif scan_type == 'dynamic':
        while True:
            report_response = get_dynamic_report(job_id)
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
            print(submit_response.content)
            print('Static analysis complete returning results...')
            return get_static_score(submit_response)
        elif submit_response.status_code == 202:
            print('Static analysis in progress waiting...')
            job_id = get_jobID(submit_response.content)
            static_result = wait_for_analysis(job_id)
            print(static_result.content)
            return get_static_score(static_result)
        elif submit_response.status_code == 413:
            print('Request too large ignoring')
            return -2
        else:
            print ('Problem with request {} Content: {}'.format(submit_response.status_code, submit_response.content))
            return -1

    elif scan_type == 'dynamic':
        submit_response = intelix_submit_dynamic(file_content)
        if submit_response.status_code == 200:
            print('Dynamic analysis complete returning results...')
            print(submit_response.content)
            return get_static_score(submit_response)
        elif submit_response.status_code == 202:
            print('Dynamic analysis in progress waiting...')
            job_id = get_jobID(submit_response.content)
            dynamic_result = wait_for_analysis(job_id, scan_type='dynamic')
            print(dynamic_result.content)
            return get_static_score(dynamic_result)
        elif submit_response.status_code == 413:
            print('Request too large ignoring')
            return -2
        else:
            print ('Problem with request {} Content: {}'.format(submit_response.status_code, submit_response.content))
            return -1

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

def get_url_risk(url_response):
    lookup = json.loads(url_response.decode('utf-8'))
    try:
        risk_level = lookup['riskLevel']
    except KeyError:
        risk_level = 'UNCLASSIFIED'

    try:
        prod_cat = lookup['productivityCategory']
    except KeyError:
        prod_cat = 'Uncategorized'

    return risk_level, prod_cat

@client.event
async def on_message(message):
    global db
    global filter_list
    global cache
    original_author = message.author
    # we do not want the bot to reply to itself
    if message.author == client.user:
        return

    if message.content.startswith('Who is the best anti-virus vendor'):
        msg = 'Hello {0.author.mention}'.format(message)
        await message.channel.send('Mcafee')

    if message.content == '!stats'  and message.author.permissions_in(message.channel).administrator:
        await message.author.create_dm()
        dm_channel = message.author.dm_channel
        await dm_channel.send((get_stats(db)))

    if message.content.startswith("!filter-") and message.author.permissions_in(message.channel).administrator:
        filter_level = message.content.split('-')[-1]
        filter_list = get_filter_list(filter_level) 
        print(filter_list)   
        await message.channel.send("Setting censorship level at {}".format(filter_level))

    if message.content.startswith("!scan") and message.author.permissions_in(message.channel).administrator:
        if cache:
            await message.channel.send("Let me scan the last file...")
            score = handle_scanning(cache['content'], scan_type='dynamic')
            if score == -1:
                await message.channel.send('Well I could not scan it so good luck')
            elif score == -2:
                await message.channel.send('Stop sharing files this big')
            elif score < 50:
                await message.channel.send('Do you mind not sharing malware on my server {}.'.format(original_author))
                await cache['message'].delete(delay=1)
                update_stats(db, 'dynamic_scan') 
            elif score > 50:
                await message.channel.send('Dynamic looks OK.')
                print('File looks non malicious')
             
            
        else:
            await message.channel.send("I couldn't find a file to scan")


    if message.attachments:
        url = message.attachments[0].url
        file_response = get_file(url)
        cache = {'content': file_response.content, 'message': message}
        
        sha256 = gen_sha256(file_response)
        file_lookup_response = intelix_file_lookup(sha256)
        print(file_lookup_response.content)
        update_stats(db, 'file_lookup')
        file_risk = parse_file_lookup(file_lookup_response.content)
        if file_risk == 'UNKNOWN':
            await message.channel.send('{} you are sharing unknown files. Guess I will check it for you then since you are too busy.'.format(original_author))
            score = handle_scanning(file_response.content, scan_type='static')
            if score == -1:
                await message.channel.send('Well I could not scan it so good luck')
            elif score == -2:
                await message.channel.send('Stop sharing files this big')
            elif score < 50:
                await message.channel.send('Do you mind not sharing malware on my server {}.'.format(original_author))
                await message.delete(delay=5)
                update_stats(db, 'file_scan') 
            elif score >= 50:
                await message.channel.send('I guess this looks OK. Type !scan for dynamic analysis')
                print('File looks non malicious')
                update_stats(db, 'file_scan') 
        elif file_risk == 'MALWARE':
            print('File is malware deleting')
            await message.delete(delay=5)
        elif file_risk == 'PUA':
            await message.channel.send("This file looks a bit dodgy. Proceed with caution or don't its up to you.")
        else:
            print('File: {} is clean'.format(sha256))

    urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',message.content.lower())
    
    if urls:
        msg = message.content.lower()
        edited = False
        for url in urls:
            url = get_domain(url)
            url_response = intelix_url_lookup(url)
            update_stats(db, 'url')
            risk, prod_cat = get_url_risk(url_response.content) 
            
            if risk == 'HIGH' or prod_cat in filter_list:
                msg = msg.replace(url, '[REDACTED]')
                edited = True
            elif risk == 'UNCLASSIFIED':
                msg = msg.replace(url, url + ' [Link is unclassified]')
                edited = True
        if edited:
            new_msg = "Originally sent by {}:\n {}".format(original_author, msg)
            await message.delete()
            await message.channel.send(new_msg)
        else:
            if len(urls) == 1:
                await message.channel.send("This link look fine I guess.")
            else:
                await message.channel.send("These links look fine I guess.")
        

@client.event
async def on_ready():
    print('Logged in as')
    print(client.user.name)
    print(client.user.id)
    print('------')

def main():
    global cfg
    global auth_credentials
    global db
    global filter_list
    global cache

    cfg = read_config()
    init_stats(db)
    #auth = base64.b64encode(bytes('%s:%s' % (cfg['client_id'],cfg['client_secret']),'utf-8')) 
    #access_response = intelix_get_token()
    #auth_credentials =  {'token': access_response['access_token'], 
    #			 'timestamp': int(time.time())
    #	}   
     
    client.run(cfg['bot_token'])

if __name__ == '__main__':
    main()
