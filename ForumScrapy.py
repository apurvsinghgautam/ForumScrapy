import time
import hashlib
import requests
from flask import *
from threading import *
from functools import wraps
from logging.config import dictConfig
from bs4 import BeautifulSoup, Comment
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
from elasticsearch.exceptions import TransportError


dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'formatter': 'default'
    }},
    'root': {
        'level': 'DEBUG',
        'handlers': ['wsgi']
    }
})


app = Flask(__name__)

'''
This function gets the latest thread and members list from the Hack Forums website, stores it in the database.
The thread keeps running indefinitely
'''
@app.before_first_request
def activate_job():
    def run_member_job():
        try:
            forums=Forums()
            forums.login()
        except (Exception, IOError, TransportError) as e:
            app.logger.error(e)
        time.sleep(15)
        member_data={
            'mappings': {
                'members': {
                    'properties': {
                        'member_name': {'type':'keyword'},
                        'member_url': {'type':'keyword'},
                        'join_date': {'type':'date', 'format':'MM-dd-yyyy'},
                        'contact_info': {'type':'text'}
                    }
                }
            }
        }
        try:
            if forums.get_elastic().indices.exists('members'):
                pass
            else:
                forums.create_index('members',member_data)
        except (Exception, IOError, TransportError) as e:
            app.logger.error(e)
        while True:
            try:
                r=get_members(forums.member_url,forums)
            except:
                app.logger.warning("Connection refused by the server")
                app.logger.warning("Retrying in few seconds")
                time.sleep(60)
                continue
            app.logger.info("Parsing members list")
            members_list, member_url =parse_members(r)
            forums.member_url=member_url
            if len(members_list) != 0:
                for member in members_list:
                    if is_stored(member):
                        continue
                    else:
                        app.logger.info("Getting member contact data")
                        try:
                            contact_info=parse_contact_info(get_contact_info(member['member_url'],forums))
                        except:
                            app.logger.warning("Connection refused by the server")
                            app.logger.warning("Retrying in few seconds")
                            time.sleep(60)
                            continue

                        if len(contact_info) == 0:
                            contact_info='--'
                        else:
                            contact_info='\n'.join(contact_info)

                        data={
                            'member_name': member['member_name'],
                            'member_url': member['member_url'],
                            'join_date': member['join_date'],
                            'contact_info':contact_info
                          }
                        app.logger.info("Storing member data")
                        try:
                            forums.get_elastic().index(index='members', doc_type='members', body=data)
                        except (Exception, IOError, TransportError) as e:
                            app.logger.error(e)


    def run_forum_job():
        try:
            forums=Forums()
            forums.login()
        except (Exception, IOError, TransportError) as e:
            app.logger.error(e)
        time.sleep(15)
        forum_data={
            'mappings': {
                'threads': {
                    'properties': {
                        'thread_title': {'type':'text'},
                        'thread_author': {'type':'text'},
                        'thread_post': {'type':'text'},
                        'thread_date': {'type':'text'},
                        'thread_url': {'type':'keyword'},
                        'forum_group': {'type':'keyword'},
                        'forum_url': {'type':'keyword'}
                    }
                }
            }
        }
        user_data={
            'mappings': {
                'users': {
                    'properties': {
                        'name': {'type':'text'},
                        'email': {'type':'keyword'},
                        'password': {'type':'keyword'}
                    }
                }
            }
        }
        try:
            if forums.get_elastic().indices.exists('forums'):
                pass
            else:
                forums.create_index('forums',forum_data)

            if forums.get_elastic().indices.exists('users'):
                pass
            else:
                forums.create_index('users',user_data)
        except (Exception, IOError, TransportError) as e:
            app.logger.error(e)
        while True:
            for key in forums.urls:
                try:
                    r1=get_forums(key,forums)
                except:
                    app.logger.warning("Connection refused by the server")
                    app.logger.warning("Retrying in few seconds")
                    time.sleep(60)
                    continue
                app.logger.info("Parsing Forums")
                links, forum_url=parse_forums(r1)
                forums.urls[key]=forum_url
                if links:
                    for link in links:
                        if is_visited(link):
                            continue
                        else:
                            try:
                                r2=get_threads(link,forums)
                            except:
                                app.logger.warning("Connection refused by the server")
                                app.logger.warning("Retrying in few seconds")
                                time.sleep(60)
                                continue
                            app.logger.info("Parsing Threads")
                            d=parse_threads(r2)
                            if d:
                                data={
                                    'thread_title': d['title'],
                                    'thread_author': d['author'],
                                    'thread_post': d['post'],
                                    'thread_date': d['date'],
                                    'thread_url': link,
                                    'forum_group': d['forum_group'],
                                    'forum_url': forums.urls[d['forum_group']]
                                }
                                app.logger.info("Storing forum data")
                                try:
                                    forums.get_elastic().index(index='forums', doc_type='threads', body=data)
                                except (Exception, IOError, TransportError) as e:
                                    app.logger.error(e)
    try:
        thread1=Thread(target=run_forum_job)
        thread2=Thread(target=run_member_job)
        thread1.start()
        thread2.start()
    except:
        app.logger.error("Caught an exception")

'''
This function displays Home page of the Forum Scrapy
'''
@app.route('/')
def index():
    return render_template("index.html")



class Forums():

    member_url='http://www.bitshacking.com/forum/members/list'
    urls = {
        'Main Discussions': 'http://www.bitshacking.com/forum/main-discussions/',
        'Exploits and Vulnerabilities': 'http://www.bitshacking.com/forum/exploits-vulnerabilities/',
        'Hacking & Security Tutorials': 'http://www.bitshacking.com/forum/hacking-security-tutorials/',
        'Beginners Hacking tutorials': 'http://www.bitshacking.com/forum/beginners-hacking-tutorials/',
        'Web Application Security & Hacking': 'http://www.bitshacking.com/forum/web-application-security-hacking/',
        'Tools & Equipment': 'http://www.bitshacking.com/forum/tools-equipment/',
        'Hacking Showoff': 'http://www.bitshacking.com/forum/hacking-showoff/',
        'Accounts and Database Section': 'http://www.bitshacking.com/forum/accounts-database-section/',
        'Freebie Leaks': 'http://www.bitshacking.com/forum/freebie-leaks/',
        'How-To Tutorials': 'http://www.bitshacking.com/forum/how-tutorials/',
        'Socks Proxy': 'http://www.bitshacking.com/forum/socks-proxy/',
        'HTTP Proxy': 'http://www.bitshacking.com/forum/http-proxy/',
        'Proxy Programs': 'http://www.bitshacking.com/forum/proxy-programs/',
        'Cracked Programs': 'http://www.bitshacking.com/forum/cracked-programs/',
        'Youtube, Twitter, and FB bots': 'http://www.bitshacking.com/forum/youtube-twitter-fb-bots/',
        'Simple Money Making Methods': 'http://www.bitshacking.com/forum/simple-money-making-methods/',
        'Black Hat Money Making': 'http://www.bitshacking.com/forum/black-hat-money-making/',
        'Links Heaven': 'http://www.bitshacking.com/forum/links-heaven/'
    }
    def __init__(self):
        self.__es=Elasticsearch()
        self.__session=requests.Session()
        self.__url='http://www.bitshacking.com/forum/hacking-security/'
        self.__headers={'User-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'}
        self.__proxies={
            'http': '<socks_proxy>',  # Enter Socks proxy
            'https': '<socks_proxy>'
        }

        self.__payload={
            'do':'login',
            's':'',
            'securitytoken':'guest',
            'vb_login_md5password':'<your_bitshacking_password_md5>',  # Enter your Bitshacking account passowrd in md5
            'vb_login_md5password_utf':'<your_bitshacking_password_md5>',
            'vb_login_password':'',
            'vb_login_username':'<your_bitshacking_username>' # Enter your Bitshacking account username
        }

        self.__cookies={
            '__atuvc':'2%7C22',
            '_ga':'GA1.2.1555749413.1527496911',
            '_gat':'1',
            '_gid':'GA1.2.624305667.1527496911',
            'bblastactivity':'0',
            'bblastvisit':'1527569520',
            'bbsessionhash':'9a683df43b075d028b670087bf9637ac'
        }




    #This function performs login to the forum
    def login(self):
        self.__session.post('http://www.bitshacking.com/forum/login.php?do=login', headers=self.__headers, data=self.__payload, proxies=self.__proxies, cookies=self.__cookies)

    #This function creates forums index
    def create_index(self,index,data):
        self.__es.indices.create(index=index, body=data)

    #This function returns elasticsearch object
    def get_elastic(self):
        return self.__es

    #This function returns the session variable
    def get_session(self):
        return self.__session

    #This function returns the headers
    def get_headers(self):
        return self.__headers

    #This function returns the Socks proxy
    def get_proxies(self):
        return self.__proxies


'''
This function takes user credentials at the time of registration and stores the details in the database
'''
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name=request.form['name']
        email=request.form['email']
        password=hashlib.sha256(str(request.form['password'])).hexdigest()
        forums=Forums()
        data={
            'query': {
                'match': {
                    'email': email
                }
            }
        }
        try:
            res=forums.get_elastic().search(index='users', body=data)
            if len(res['hits']['hits']) != 0:
                flash('Email Already Registered','msg')
                return redirect(url_for('register'))
            else:
                forums.get_elastic().index(index='users', doc_type='users', body={'name':name, 'email':email, 'password':password})
        except (Exception, IOError, TransportError) as e:
            app.logger.error(e)

        flash('You are now registered and can log in','success')
        return redirect(url_for('login'))
    return render_template('auth/register.html')


'''
This function takes user credentials at the time of login and authenticates the user
'''
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email=request.form['email']
        password_candidate=hashlib.sha256(str(request.form['password'])).hexdigest()
        forums=Forums()
        data={
            'query': {
                'match': {
                    'email': email
                }
            }
        }

        try:
            res=forums.get_elastic().search(index='users', body=data)
            if len(res['hits']['hits']) != 0:
                #Get stored password hash
                name=res['hits']['hits'][0]['_source']['name']
                email=res['hits']['hits'][0]['_source']['email']
                password=res['hits']['hits'][0]['_source']['password']

                #Compare Passwords
                if password_candidate == password:
                    session['logged_in']=True
                    session['name']=name
                    session['email']=email
                    flash('You are now logged in','success')
                    return redirect(url_for('index'))
                else:
                    error='Invalid Email/Password'
                    return render_template('auth/login.html',error=error)
            else:
                error='Invalid Email/Password'
                return render_template('auth/login.html',error=error)

        except (Exception, IOError, TransportError) as e:
            app.logger.error(e)
    return render_template('auth/login.html')


'''
This function is used to check whether a session is valid or not
'''
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


'''
This function is used to invalidate the session and logout the user
'''
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


'''
This function is used to get the threads from the database
'''
@app.route('/get_latest_threads/<string:page>')
@is_logged_in
def get_latest_threads(page):
    forums=Forums()
    data={
        'from': ((decode(page)-1)*10),
        'size': 10,
        'query': {
            'match_all':{

            }
        }
    }

    if decode(page) <= 0:
        return render_template('404.html')
    else:
        try:
            res=forums.get_elastic().search(index='forums', body=data)
            if res['hits']['hits'] is None:
                flash('No Data Found','danger')
                return render_template("get_latest_threads.html",lthread=[], page=page)
            else:
                return render_template("get_latest_threads.html",lthread=res, page=page)
        except (Exception, IOError, TransportError) as e:
            app.logger.error(e)


'''
This function is used to get details about a particular thread
'''
@app.route('/get_data/<string:group>/<string:id>')
def get_data(group,id):
    thread_url='http://www.bitshacking.com/forum/'+group+'/'+id
    forums=Forums()
    data={
        'query': {
            'match': {
                'thread_url': thread_url
            }
        }
    }

    try:
        res=forums.get_elastic().search(index='forums', body=data)
        return render_template("get_data.html", lthread=res)
    except (Exception, IOError, TransportError) as e:
        app.logger.error(e)


'''
This function is used to get searched threads
'''
@app.route('/search_threads', methods=['GET','POST'])
@is_logged_in
def search_threads():
    if request.method == 'POST':
        search_text=request.form['search']
        group=request.form['group']
        forums=Forums()
        if len(group) == 0:
            data={
                'query': {
                    'match': {
                        'thread_title': search_text
                    }
                }
            }

        else:
            data={
                "query": {
                    "bool": {
                        "must": [
                            {"match": {
                                "thread_title": search_text
                            }},
                            {"match":{
                                "forum_group": group
                            }}
                        ]
                    }
                }
            }

        if not search_text:
            return render_template('get_searched_threads.html')
        else:
            try:
                res=forums.get_elastic().search(index='forums', body=data)
                if res['hits']['hits'] is None:
                    return render_template("get_searched_threads.html",lthread=[])
                else:
                    return render_template("get_searched_threads.html",lthread=res)
            except (Exception, IOError, TransportError) as e:
                app.logger.error(e)


'''
This function is used to get the members list from the database
'''
@app.route('/get_members_list/<string:page>')
def get_members_list(page):
    forums=Forums()
    data={
        'from': ((decode(page)-1)*10),
		'size': 10,
		'query': {
			'match_all':{

			}
		}
	}
    if decode(page) <= 0:
        return render_template('404.html')
    else:
        try:
            res = forums.get_elastic().search(index='members', body=data)
            if res['hits']['hits'] is None:
                flash('No Data Found', 'danger')
                return render_template("get_members_list.html", memlist=[], page=page)
            else:
                return render_template("get_members_list.html", memlist=res, page=page)
        except (Exception, IOError, TransportError) as e:
            app.logger.error(e)


'''
This function is used to encode string using Base64 and is called during context processing in Jinja2
'''
@app.context_processor
def utility_processor():
    def encode(data):
        return str(data).encode('base64').strip('\r\n')
    return dict(encode=encode)

#This function is used to get the Forums information
def get_forums(data,forums):
    r=forums.get_session().get(forums.urls[data], headers=forums.get_headers(), proxies=forums.get_proxies())
    return r.text

#This function is used to get the particular threads information
def get_threads(data,forums):
    r=forums.get_session().get(data, headers=forums.get_headers(), proxies=forums.get_proxies())
    return r.text

#This function is used to get the members information
def get_members(data,forums):
    r=forums.get_session().get(data, headers=forums.get_headers(), proxies=forums.get_proxies())
    return r.text

def get_contact_info(data,forums):
    r = forums.get_session().get(data, headers=forums.get_headers(), proxies=forums.get_proxies())
    return r.text

#This function is used to parse information from particular forums
def parse_forums(data):
    links=[]
    soup=BeautifulSoup(data,'html.parser')
    rows=soup.find_all('tbody')
    rows=rows[1].find_all('a')
    for row in rows:
        if row.text and row.has_attr('id'):
            link=row.get('href')
            links.append(link)
        else:
            pass
    if soup.find('a', {'class':'smallfont', 'rel':'next'}):
        forum_url=soup.find('a', {'class':'smallfont', 'rel':'next'}).get('href')
    else:
        forum_url='http://www.bitshacking.com/forum/'+soup.find('a', {'id':'community'}).get('href')[4]
    return links, forum_url

#This function is used to parse information from particular threads
def parse_threads(data):
    d={}
    soup=BeautifulSoup(data,'html.parser')
    if soup.find('a',{'class':'bigusername'}) is not None:
        forum_group=soup.find('h2', {'class':'myh2'}).text
        title=soup.find('h1',{'class':'myh1'}).text
        author=soup.find('a',{'class':'bigusername'}).text
        post=soup.find('div',{'class':'vb_postbit'}).text
        post_data=soup.find('div',{'class':'vb_postbit'})
        for link in post_data.find_all('a'):
            post=post + '\n' + link.get('href')
        comm=[]
        for comment in soup.find_all(text=lambda text:isinstance(text, Comment)):
            if 'status icon and date' in comment:
                comm.append(comment.next_element.strip())

        if 'Yesterday' in comm[1]:
            yesterday=datetime.today()-timedelta(1)
            date=yesterday.strftime('%m-%d-%Y')+", "+comm[1].split(',')[1].strip()
        elif 'Today' in comm[1]:
            today=datetime.today()
            date=today.strftime('%m-%d-%Y')+", "+comm[1].split(',')[1].strip()
        else:
            date=comm[1]
        d={
            'forum_group': forum_group,
            'title': title,
            'author': author,
            'post': post,
            'date': date
        }
    return d

#This function is used to parse particular member's information
def parse_members(data):
    members_list=[]
    soup=BeautifulSoup(data,'html.parser')
    table=soup.find_all('table', {'class':'tborder'})
    rows=table[4].find_all('tr')
    for row in rows:
        if (row.find('td', {'class':'alt1Active'}) and row.find('td', {'class':'alt2'})) is not None:
            member_data={
                'member_name':row.find('td', {'class':'alt1Active'}).find('a').text,
                'member_url':row.find('td', {'class':'alt1Active'}).find('a').get('href'),
                'join_date':row.find('td', {'class':'alt2'}).text.strip()
            }
            members_list.append(member_data)
    if soup.find('a', {'class':'smallfont', 'rel':'next'}):
        member_url=soup.find('a', {'class':'smallfont', 'rel':'next'}).get('href')
    else:
        member_url='http://www.bitshacking.com/forum/members/list'
    return members_list, member_url

def parse_contact_info(data):
    contact_info=[]
    soup=BeautifulSoup(data,'html.parser')
    if soup.find('ul', {'id':'instant_messaging_list'}):
        rows=soup.find('ul', {'id':'instant_messaging_list'}).find_all('li')
        for row in rows:
            service=row.find('span', {'class':'smallfont shade'}).text
            service_id=row.find('a', {'class':'im_txt_link'}).text
            details=service+'\n'+service_id
            contact_info.append(details)
    return contact_info


#This function is used to check whether the thread URL is already visited by the program or not
def is_visited(data):
    forums=Forums()
    data={
        'query': {
            'match': {
                'thread_url': data
            }
        }
    }
    try:
        res=forums.get_elastic().search(index='forums', body=data)
        if len(res['hits']['hits']) != 0:
            return True
        else:
            return False
    except (Exception, IOError, TransportError) as e:
        app.logger.error(e)

#This function is used to check whether the member is already stored in the database or not
def is_stored(data):
    forums=Forums()
    data={
        'query': {
            'match': {
                'member_name': data['member_name']
            }
        }
    }
    try:
        res = forums.get_elastic().search(index='members', body=data)
        if len(res['hits']['hits']) != 0:
            return True
        else:
            return False
    except (Exception, IOError, TransportError) as e:
        app.logger.error(e)

#This function encodes the string using Base64
def encode(data):
    return str(data).encode('base64').strip('\r\n')


#This function decodes the string using Base64
def decode(data):
    return int(data.decode('base64'))


if __name__ == '__main__':
    app.secret_key = '<your_secret_key>' # Enter the Flask secret key
    app.run(debug=True)
