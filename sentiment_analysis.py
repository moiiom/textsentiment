# -*- coding: utf-8 -*-
import sys
import random
import time
import base64
import hmac
import MySQLdb
import requests
from hashlib import sha1
from urllib import quote
import warnings

reload(sys)
sys.setdefaultencoding("utf-8")
warnings.filterwarnings("ignore")

# baidu wenzi secret id, secret key
secret_id = "AKID54tfhWkSpcwhNobMJ9pKMI3fbSEuPs62"
secret_key = "75sWdieP4aw8NXjpXgOr7HOfglouoZfC"
signature_url = "GETwenzhi.api.qcloud.com/v2/index.php?Action=TextSentiment&Nonce={nonce}&Region=sz&SecretId={secretid}&Timestamp={timestamp}&content={content}"
final_url = "https://wenzhi.api.qcloud.com/v2/index.php?Action={action}&Nonce={nonce}&Region={region}&SecretId={secretid}&Timestamp={timestamp}&Signature={signature}&content={content}"


class CMySql:
    def __init__(self, host, user, pwd, db, port=3306):
        self.host = host
        self.user = user
        self.pwd = pwd
        self.port = port
        self.db = db
        self.conn = ''
        self.bConn = False

    def execute(self, sql):
        try:
            if self.bConn is False:
                self.conn = MySQLdb.connect(host=self.host, user=self.user, passwd=self.pwd, port=self.port,
                                            charset='utf8')
                self.bConn = True

            cur = self.conn.cursor()
            self.conn.select_db(self.db)
            count = cur.execute(sql)
            results = cur.fetchall()
            self.conn.commit()
            cur.close()
            return results, count
        except MySQLdb.Error, e:
            print "Mysql Error %d: %s" % (e.args[0], e.args[1])
            self.conn.close()
            self.bConn = False
            raise


def make_request_url(content):
    nonce = random.randint(100000, 999999)
    timestamp = int(time.time())

    _url = signature_url.format(nonce=nonce, secretid=secret_id, timestamp=timestamp, content=content)
    hashed_signature = hmac.new(secret_key, _url, sha1).digest()
    base64_signature = base64.b64encode(hashed_signature)
    encode_signature = quote(base64_signature)
    encode_content = quote(content.encode('utf-8'))

    url = final_url.format(action="TextSentiment", nonce=nonce, region="sz", secretid=secret_id, timestamp=timestamp,
                           signature=encode_signature, content=encode_content)
    return url


def content_analysis(content):
    # positive_score = ""
    # negative_score = ""
    url = make_request_url(content)
    r = requests.get(url, verify=False)
    time.sleep(1)
    # obj = json.loads(r.text)
    # if obj["code"] == 0 and obj["codeDesc"] == "Success":
    #     positive_score = str(obj["positive"])
    #     negative_score = str(obj["negative"])
    # else:
    #     positive_score = "--"
    #     negative_score = "--"
    # return positive_score + "," + negative_score
    return r.text


def main():
    conn = CMySql("192.168.1.1", "busi_read", "8dF5T8ASPjhGchu2", "busi_read")
    sql = "select id,remark from buz_audit_log order by add_time desc;"
    results, count = conn.execute(sql)
    if results:
        for it in results:
            tid = it[0]
            remark = it[1]
            print str(tid) + "\t" + remark + "\t" + content_analysis(remark)


if __name__ == '__main__':
    main()
