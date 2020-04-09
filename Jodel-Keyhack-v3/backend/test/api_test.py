from time import sleep

import jodel_api
import hmac, hashlib

from jodel_api import gcmhack

if __name__ == '__main__':
    lat, lng, city = 48.148434, 11.567867, "Munich"
    account = gcmhack.AndroidAccount()
    sleep(5)
    token = account.get_push_token()
    j = jodel_api.JodelAccount(lat=lat, lng=lng, city=city, pushtoken=token)
    print('Account created')
    print('Verification: {}'.format(j.verify(android_account=account)))
    print(j.get_posts_popular())
    print('Karma is: {}'.format(j.get_karma()))
    print(j.upvote('5d238be544a6a0001a0360d6'))
    print('Karma is: {}'.format(j.get_karma()))

    #req = 'POST%api.go-tellm.com%443%/api/v2/users/%%%2019-01-10T21:11:59Z%%{"location":{"country":"DE","city":"Heilbronn","loc_coordinates":{"lng":9.2070918,"lat":49.1208046},"loc_accuracy":16.581},"registration_data":{"channel":"","provider":"branch.io","campaign":"","feature":"","referrer_branch_id":"","referrer_id":""},"client_id":"81e8a76e-1e02-4d17-9ba0-8a7020261b26","device_uid":"573b2e648c7b3849f1a533167354f4752f0466010c72bdde378a5d856421b122","language":"de-DE"}'

    #signature = hmac.new('TNHfHCaBjTvtrjEFsAFQyrHapTHdKbJVcraxnTzd'.encode("utf-8"), req.encode("utf-8"), hashlib.sha1).hexdigest().upper()
    #print(signature)
