import requests

class RspamMessage(object):
  def __init__(self, ip, helo, hostname, mailfrom, queue_id, rcpt, subject, check_filters='all'):
    self.Ip = ip
    self.Helo = helo
    self.Hostname = hostname
    self.From = mailfrom
    self.queue_id = queue_id
    self.Rcpt = rcpt
    self.Subject = subject
    self.Pass = check_filters

    self.body = None

  @property
  def headers(self):
    headers = dict(self.__dict__)
    del headers['body']
    del headers['queue_id']
    headers['Queue-Id'] = self.queue_id
    return headers

  def set_headers(self, **headers):
    ''' Use '_' if the parameter has a '-'
    '''
    for header, value in headers.items():
      self.__dict__[header] = value

  def __repr__(self):
    return '<RspamMessage %r>' % self.From

class Rspamd(object):
  def __init__(self, rspamd_server='localhost', rspamd_port=11334, rspamd_web_password='q1'):
    self.server = ':'.join((rspamd_server, str(rspamd_port)))
    self.password = rspamd_web_password

  def learn_ham(self, rmsg):
    rmsg.set_headers(Password = self.password)
    r = requests.post('http://%s/learnham' % self.server, headers = rmsg.headers, data = rmsg.body)
    return r.json(), r.status_code

  def learn_spam(self, rmsg):
    rmsg.set_headers(Password = self.password)
    r = requests.post('http://%s/learnspam' % self.server, headers = rmsg.headers, data = rmsg.body)
    return r.json(), r.status_code

  def check(self, rmsg):
    rmsg.set_headers(Password = self.password)
    r = requests.post('http://%s/check' % self.server, headers = rmsg.headers, data = rmsg.body)
    return r.json(), r.status_code

if __name__ == '__main__':
  import json

  msg = RspamMessage(
    ip = '23.88.105.107',
    helo = 'mundoloko',
    hostname = 'blaster.com',
    mailfrom = 'sandro@inova.net',
    queue_id = '10199D830F',
    rcpt = 'sandromll@gmail.com',
    subject = 'Viagra XXX',
  )

  msg.body = body
  rspamd = Rspamd()
  result, scode = rspamd.learn_ham(msg)
  print 'Learn Ham', scode
  result, scode = rspamd.learn_spam(msg)
  print 'Learn Spam', scode
  result, scode = rspamd.check(msg)
  print json.dumps(result, indent=2)