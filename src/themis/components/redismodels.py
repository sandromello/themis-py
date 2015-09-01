from redisco import models
import json

POLICY_TYPES = ['bypass', 'regular', 'bypass+']
JAILBY_VALUES = [ 'SASLUsername', 'SenderIP', 'Sender', 'Sender+', 'SenderDomain', 'SenderDomain+' ]
JAILACTION_VALUES = ['block', 'hold', 'monitor']
RESERVED_NAMES = ['main', 'any']

class Encoder(json.JSONEncoder):
  def default(self, o):
    return o.namespace

class Base(models.Model):
  def validate(self):
    if self._errors:
      raise ValueError(self._errors)

  def asjson(self, indent=False):
    if indent:
      return json.dumps(self.as_dict, indent=2, cls=Encoder)
    return json.dumps(self.as_dict, cls=Encoder)

  @property
  def asdict(self):
    response = self.attributes_dict
    response['id'] = self.id
    return response

class MetaData(Base):
  namespace = models.Attribute(required=True, unique=True)
  manual_block = models.BooleanField(default=False)
  bypass = models.BooleanField(default=False, indexed=True)
  last_upadate = models.DateField(auto_now=True)

  def __repr__(self):
    return '<MetaData %r>' % self.namespace

class ActionHeader(Base):
  namespace = models.Attribute(required=True)
  lookup_header = models.Attribute(required=True)
  regexp_value = models.Attribute(required=True)
  new_header = models.Attribute(required=True)
  new_header_value = models.Attribute(required=True)

  def __repr__(self):
    return '<ActionHeader %r>' % self.namespace

class Policy(Base):
  namespace = models.Attribute(required=True, unique=True)
  enable = models.BooleanField(default=True)
  # regular/bypass/bypass+
  type = models.Attribute(default='regular')
  priority = models.FloatField(default=5.0)
  source = models.ReferenceField('Group', required=True)
  destination = models.ReferenceField('Group', required=True)
  # SASLUsername, SenderIP, Sender, Sender+, SenderDomain, SenderDomain+
  jailby = models.Attribute(default='Sender+')
  # block, hold, monitor
  jailaction = models.Attribute(default='monitor')
  jailspec = models.Attribute(default='0:0')
  pool = models.ReferenceField('Pool')

  stophere = models.BooleanField(default=False)
  requestsmon = models.BooleanField(default=False)
  countrcpt = models.BooleanField(default=True)
  
  
  replydata = models.Attribute(default='Limit reached. Blocking for %s second(s)', indexed=False)
  onlyheaders = models.BooleanField(default=False)
  spf = models.BooleanField(default=False)
  # Should be another model
  actionheaders = models.ListField(ActionHeader)

  def __repr__(self):
    return '<Policy %r>' % self.namespace

class Pool(Base):
  namespace = models.Attribute(required=True, unique=True)
  servers = models.ListField(str, default=['any'])

  def __repr__(self):
    return '<Pool %r>' % self.namespace

class Group(Base):
  namespace = models.Attribute(required=True, unique=True)
  items = models.ListField(str)

  def __repr__(self):
    return '<Group %r>' % self.namespace
