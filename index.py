import os
import ydb

import string
import random
import time

import hashlib 

driver = ydb.Driver(endpoint=os.getenv('YDB_ENDPOINT'), database=os.getenv('YDB_DATABASE'))
driver.wait(fail_fast=True, timeout=5)
pool = ydb.SessionPool(driver)

def token_generator(size, chars=string.ascii_uppercase + string.ascii_lowercase + string.digits + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def compare_password_and_hash(password_from_user, hashed_password_from_database, userid):
    hashed_password_from_user = hashlib.sha512(password_from_user.encode('utf-8') + \
                                                userid.encode('utf-8')).hexdigest()
    return hashed_password_from_user==hashed_password_from_database

def query_generator_get_id_and_hashed_password(login):
   return  """
   SELECT id, password FROM users WHERE login == "{}";
   """.format(login)

def execute_query_get_id_and_hashed_password(session):
  return session.transaction().execute(
    query,
    commit_tx=False,
    settings=ydb.BaseRequestSettings().with_timeout(3).with_operation_timeout(2)
  )

def query_generator_write_token(userid, token):
   return  """
   UPDATE users 
   SET token = "{}", last_seen = {} 
   WHERE id == "{}";
   """.format(token, int(time.time()), userid)

def execute_query_write_token(session):
  return session.transaction().execute(
    query,
    commit_tx=True,
    settings=ydb.BaseRequestSettings().with_timeout(3).with_operation_timeout(2)
  )

def handler(event, context):

    try:
        login_from_user = event['queryStringParameters']["login"]
        password_from_user = event['queryStringParameters']["password"]

        #select id and hashed password by login
        global query
        query = query_generator_get_id_and_hashed_password(login_from_user)
        id_and_password = pool.retry_operation_sync(execute_query_get_id_and_hashed_password)

        if not id_and_password[0].rows:
          return {
                  'statusCode': 200,
                  'body': {
                          "message": "Username or password is incorrect",
                          "status": False
                          }
                 }

        userid = id_and_password[0].rows[0]["id"]
        hashed_password_from_database = id_and_password[0].rows[0]["password"]


                
        if compare_password_and_hash(password_from_user, hashed_password_from_database, userid):

            token = token_generator(80)

            query = query_generator_write_token(userid, token)
            
            pool.retry_operation_sync(execute_query_write_token)
            
            return {
                  'statusCode': 200,
                  'body': {
                  "message": "Welcome!",
                  "name": login_from_user, 
                  "token": token,
                  "status": True
                    }
                }
        else:
            return {
            'statusCode': 200,
            'body': {
            "message": "Username or password is incorrect",
            "status": False
                    }
                }

    except Exception as exception:
        return {
                  'statusCode': 200,
                  'body': {
                      "message": "Something went wrong.",
                      "error" : type(exception).__name__,
                      "event" : event,
                      "status": False,
                      "query" : query
                          }
                }
        
