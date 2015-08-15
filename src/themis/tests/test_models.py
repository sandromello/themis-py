import unittest, sys, json, uuid
from datetime import datetime
from redisco import connection_setup
from themis.models import Policy, Group, MetaData, ActionHeader, Pool
from redis import StrictRedis

class PolicyTestCase(unittest.TestCase):
  def test_policy_crud_operations(self):
    connection_setup(host='redishost')
    group = Group(
      namespace = 'velox',
      groups = ['veloxmail.com.br', 'velox.com.br']
    )
    #group.validate()
    #print group.is_valid()

    #print group.errors
    group.save()
    result = Group.objects.filter(namespace='velox')
    print result

    ah = ActionHeader(
      namespace = 'spam-zimbra',
      lookup_header = 'X-CMAE-Score',
      regexp_value = 'spam',
      new_header = 'X-SPAM-Flag',
      new_header_value = 'YES'
    )
    ah.save()

    pool = Pool(namespace = 'main')
    pool.save()

    p = Policy(
      namespace = 'velox',
      source = result[0],
      destination = result[0],
      actionheaders = [ActionHeader.objects.filter(namespace='spam-zimbra')[0]]
    )
    p.save()


    

    
    
    print Policy.objects.all().order('priority')[0].asjson(True)
    r = StrictRedis('redishost')
    r.flushdb()
    #policy =  Policy.objects.filter(namespace='velox')[0]
    #print policy.asjson(True)


if __name__ == '__main__':
  suite = unittest.TestSuite()
  suite.addTest(PolicyTestCase('test_policy_crud_operations'))
  unittest.TextTestRunner().run(suite)