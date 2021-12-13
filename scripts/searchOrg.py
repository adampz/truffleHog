"""
Credit for this code goes to https://github.com/ryanbaxendale 
via https://github.com/dxa4481/truffleHog/pull/9
"""
import requests
from truffleHog import truffleHog
import re
from json import loads, dumps

rules = {
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Adobe Client (Oauth Web)": "(?i)(adobe[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{32})['\"]",
    #"Adobe Client Secret": "(p8e-)(?i)[a-z0-9]{32}",
    #"Alibaba AccessKey ID": "(LTAI)(?i)[a-z0-9]{20}",
    "Alibaba Secret Key": "(?i)(alibaba[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{30})['\"]",
    "Asana Client ID": "(?i)(asana[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9]{16})['\"]",
    "Asana Client Secret": "(?i)(asana[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{32})['\"]",
    "Atlassian API token": "(?i)(atlassian[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{24})['\"]",
    "AWS API Key": "((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})",
    "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS API Key": "AKIA[0-9A-Z]{16}",
    "AWS AppSync GraphQL Key": "da2-[a-z0-9]{26}",
    "Bitbucket client ID": "(?i)(bitbucket[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{32})['\"]",
    "Bitbucket client secret": "(?i)(bitbucket[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9_\-]{64})['\"]",
    "Beamer API token": "(?i)(beamer[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](b_[a-z0-9=_\-]{44})['\"]",
    #"Clojars API token": "(CLOJARS_)(?i)[a-z0-9]{60}",
    "Contentful delivery API token": "(?i)(contentful[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9\-=_]{43})['\"]",
    "Contentful preview API token": "(?i)(contentful[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9\-=_]{43})['\"]",
    "Databricks API token": "dapi[a-h0-9]{32}",
    "Discord API key": "(?i)(discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{64})['\"]",
    "Discord client ID": "(?i)(discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9]{18})['\"]",
    "Discord client secret": "(?i)(discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9=_\-]{32})['\"]",
    #"Doppler API token": "['\"](dp\.pt\.)(?i)[a-z0-9]{43}['\"]",
    "Dropbox API secret/key": "(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{15})['\"]",
    "Dropbox API secret/key": "(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{15})['\"]",
    "Dropbox short lived API token": "(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](sl\.[a-z0-9\-=_]{135})['\"]",
    "Dropbox long lived API token": "(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"][a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43}['\"]",
    #"Duffel API token": "['\"]duffel_(test|live)_(?i)[a-z0-9_-]{43}['\"]",
    #"Dynatrace API token": "['\"]dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}['\"]",  
    #"EasyPost API token": "['\"]EZAK(?i)[a-z0-9]{54}['\"]",
    #"EasyPost test API token": "['\"]EZTK(?i)[a-z0-9]{54}['\"]",
    "Facebook token": "(?i)(facebook[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{32})['\"]",
    "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]",
    "Fastly API token": "(?i)(fastly[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9\-=_]{32})['\"]",
    "Finicity client secret": "(?i)(finicity[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{20})['\"]",
    "Finicity API token": "(?i)(finicity[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{32})['\"]",
    #"Flutterweave public key": "FLWPUBK_TEST-(?i)[a-h0-9]{32}-X",
    #"Flutterweave secret key": "FLWSECK_TEST-(?i)[a-h0-9]{32}-X",
    #"Flutterweave encrypted key": "FLWSECK_TEST[a-h0-9]{12}",
    #"Frame.io API token": "fio-u-(?i)[a-z0-9-_=]{64}",
    "Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Generic API Key": "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]",
    "Generic Secret": "[sS][eE][cC][rR][eE][tT].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Generic Secret": "[s|S][e|E][c|C][r|R][e|E][t|T].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]",
    "GitLab Personal Access Token": "glpat-[0-9a-zA-Z\-]{20}",
    "GitHub Personal Access Token": "ghp_[0-9a-zA-Z]{36}",
    "Github OAuth Access Token":  "gho_[0-9a-zA-Z]{36}",
    "Github App Token": "(ghu|ghs)_[0-9a-zA-Z]{36}",
    "Github Refresh Token": "ghr_[0-9a-zA-Z]{76}",
    #"GoCardless API token": "['\"]live_(?i)[a-z0-9-_=]{40}['\"]",
    "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google (GCP) Service-account": "\"type\": \"service_account\"",
    "Google OAuth Access Token": "ya29\\.[0-9A-Za-z\\-_]+",
    #"Grafana API token": "['\"]eyJrIjoi(?i)[a-z0-9-_=]{72,92}['\"]",    
    #"Hashicorp Terraform user/org API token": "['\"](?i)[a-z0-9]{14}\.atlasv1\.[a-z0-9-_=]{60,70}['\"]",
    "Heroku API Key": "[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Hubspot API token": "(?i)(hubspot[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]",
    "Intercom API token": "(?i)(intercom[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9=_]{60})['\"]",
    "Intercom client secret/ID": "(?i)(intercom[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]",
    #"Ionic API token": "ion_(?i)[a-z0-9]{42}",
    #"Linear API token": "lin_api_(?i)[a-z0-9]{40}",
    "Linear client secret/ID": "(?i)(linear[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{32})['\"]",
    "Linkedin Client secret": "(?i)(linkedin[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z]{16})['\"]",
    "Linkedin Client ID": "(?i)(linkedin[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{14})['\"]",
    "Lob API Key": "(?i)(lob[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]((live|test)_[a-f0-9]{35})['\"]",
    "Lob Publishable API Key": "(?i)(lob[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]((test|live)_pub_[a-f0-9]{31})['\"]",
    "Mailchimp API key": "(?i)(mailchimp[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{32}-us20)['\"]",
    "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
    "Mailgun private API token": "(?i)(mailgun[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](key-[a-f0-9]{32})['\"]",
    "Mailgun public validation key": "(?i)(mailgun[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](pubkey-[a-f0-9]{32})['\"]",
    "Mailgun webhook signing key": "(?i)(mailgun[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})['\"]",
    #"Mapbox API token": "(?i)(pk\.[a-z0-9]{60}\.[a-z0-9]{22}",
    "MessageBird API token": "(?i)(messagebird[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{25})['\"]",
    "MessageBird API client ID": "(?i)(messagebird[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]",
    "New Relic user API Key": "['\"](NRAK-[A-Z0-9]{27})['\"]",
    "New Relic user API ID": "(?i)(newrelic[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([A-Z0-9]{64})['\"]",
    "New Relic ingest browser API token": "['\"](NRJS-[a-f0-9]{19})['\"]",
    #"npm access token": "['\"](npm_(?i)[a-z0-9]{36})['\"]",
    "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
    "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "Picatic API Key": "sk_live_[0-9a-z]{32}",
    #"Planetscale password": "pscale_pw_(?i)[a-z0-9\-_\.]{43}",
    #"Planetscale API token": "pscale_tkn_(?i)[a-z0-9\-_\.]{43}",
    #"Postman API token": "PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34}",
    "Pulumi API token": "pul-[a-f0-9]{40}",
    "PyPI upload token": "pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,1000}",
    "Rubygem API token": "rubygems_[a-f0-9]{48}",
    #"SendgrAPI token": "SG\.(?i)[a-z0-9_\-\.]{66}",
    #"Sendinblue API token": "xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16}",
    "Shippo API token": "shippo_(live|test)_[a-f0-9]{40}",
    "Shopify shared secret": "shpss_[a-fA-F0-9]{32}",
    "Shopify access token": "shpat_[a-fA-F0-9]{32}",
    "Shopify custom app access token": "shpca_[a-fA-F0-9]{32}",
    "Shopify private app access token": "shppa_[a-fA-F0-9]{32}",
    "Slack Webhook": "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Slack Token": "(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "Stripe Access Token": "(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}",
    "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
    "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
    "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
    "Telegram Bot API Key": "[0-9]+:AA[0-9A-Za-z\\-_]{33}",
    "Twilio API Key": "SK[0-9a-fA-F]{32}",
    "Twitch API token": "(?i)(twitch[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{30})['\"]",
    "Twitter Access Token": "[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Twitter token": "(?i)(twitter[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-f0-9]{35,44})['\"]",
    "Twitter OAuth": "[tT][wW][iI][tT][tT][eE][rR].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
    #"Typeform API token": "(?i)(typeform[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}(tfp_[a-z0-9\-_\.=]{59}",
}

for key in rules:
    rules[key] = re.compile(rules[key])

def get_org_repos(orgname, page):
    response = requests.get(url='https://api.github.com/users/orgname/repos?page={}'.format(page))
    json = response.json()
    if not json:
        return None
    for item in json:

        if item['fork'] == False:
            print('searching ' + item["html_url"])
            results = truffleHog.find_strings(item["html_url"], do_regex=True, custom_regexes=rules, do_entropy=False, max_depth=100000)
            for issue in results["foundIssues"]:
                d = loads(open(issue).read())
                d['github_url'] = "{}/blob/{}/{}".format(item["html_url"], d['commitHash'], d['path'])
                d['github_commit_url'] = "{}/commit/{}".format(item["html_url"], d['commitHash'])
                d['diff'] = d['diff'][0:200]
                d['printDiff'] = d['printDiff'][0:200]
                print(dumps(d, indent=4))
    get_org_repos(orgname, page + 1)
get_org_repos("orgname", 1)
