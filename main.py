import session as vk
from config import user_login, user_password

user_api = vk.UserAPI(user_login=user_login, user_password=user_password, scope='offline,wall', v='5.131')

