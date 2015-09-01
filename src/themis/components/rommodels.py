import rom as models
import json, datetime

POLICY_TYPES = ['bypass', 'regular', 'bypass+']
JAILBY_VALUES = [ 'SASLUsername', 'SenderIP', 'Sender', 'Sender+', 'SenderDomain', 'SenderDomain+' ]
JAILACTION_VALUES = ['block', 'hold', 'monitor']
RESERVED_NAMES = ['main', 'any']

class Encoder(json.JSONEncoder):
  def default(self, o):
    return o.namespace

class Base(models.Model):
  pass
  #def validate(self):
  #  if self._errors:
  #    raise ValueError(self._errors)

  #def asjson(self, indent=False):
  #  if indent:
  #    return json.dumps(self.attributes_dict, indent=2, cls=Encoder)
  #  return json.dumps(self.attributes_dict, cls=Encoder)

  #@property
  #def asdict(self):
  #  return self.attributes_dict

class MetaData(Base):
  namespace = models.String(required=True, unique=True, index=True)
  manual_block = models.Boolean(default=False, index=True)
  bypass = models.Boolean(default=False, index=True)
  last_upadate = models.DateTime(required=True, index=True, default=datetime.datetime.now())

  def __repr__(self):
    return '<MetaData %r>' % self.namespace

class Policy(Base):
  namespace = models.String(required=True, unique=True, index=True)
  enable = models.Boolean(default=True, index=True)
  # regular/bypass/bypass+
  type = models.String(default='regular', index=True)
  priority = models.Float(default=5.0, index=True)
  source = models.OneToOne('Group', required=True)
  destination = models.OneToOne('Group', required=True)
  # SASLUsername, SenderIP, Sender, Sender+, SenderDomain, SenderDomain+
  jailby = models.String(default='Sender+', index=True)
  # block, hold, monitor
  jailaction = models.String(default='monitor', index=True)
  jailspec = models.String(default='0:0')
  pool = models.OneToOne('Pool', on_delete='cascade')

  stophere = models.Boolean(default=False, index=True)
  requestsmon = models.Boolean(default=False)
  countrcpt = models.Boolean(default=True, index=True)
  
  
  replydata = models.String(default='Limit reached. Blocking for %s second(s)')
  onlyheaders = models.Boolean(default=False, index=True)
  spf = models.Boolean(default=False, index=True)
  # Should be another model
  actionheaders = models.OneToMany('ActionHeader')

  def __repr__(self):
    return '<Policy %r>' % self.namespace

class Pool(Base):
  namespace = models.String(required=True, unique=True, index=True)
  servers = models.ListField(str, default=['any'])

  def __repr__(self):
    return '<Pool %r>' % self.namespace

class Group(Base):
  namespace = models.String(required=True, unique=True, index=True)
  groups = models.ListField(str, default=['any'])

  def __repr__(self):
    return '<Group %r>' % self.namespace

class ActionHeader(Base):
  namespace = models.String(required=True, index=True)
  lookup_header = models.String(required=True)
  regexp_value = models.String(required=True)
  new_header = models.String(required=True)
  new_header_value = models.String(required=True)

  def __repr__(self):
    return '<ActionHeader %r>' % self.namespace
