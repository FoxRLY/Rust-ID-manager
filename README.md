Сервис авторизации и аутентификации пользователей

Что умеет делать?:
- Проводить регистрацию новых пользователей
- Выдавать JWT токены (рефреш и доступ)
- Обновлять пары токенов
- Помечать семейство токенов как утекшие, если они использовались более одного раза

Используемые решения:
- Postgres для хранения данных о пользователе
- Redis для временного хранения использованных токенов

API:
Все эндпоинты должны быть вызваны со специальныцм паролем доступа к сервису в заголовке Authentication.
- ```/register + RegistrationInfo = {id: id_пользователя}``` - эндпоинт регистрации, в тело запроса необходимо сложить данные о пользователе
- ```/login + AuthenticationInfo = Tokens``` - эндпоинт входа, выдает токены в ответ на валидные входные данные
- ```/refresh + Tokens = Tokens``` - эндпоинт обновления токенов, возвращает новые в ответ на валидные старые

```RegistrationInfo``` = ```{
    "name": "FoxRLY",
    "email": "nfdkf6@gmail.com",
    "role": "Borgar",
    "password": "1337"
}```

```AuthenticationInfo``` = ```{
    "email": "dsflksd@gmail.com",
    "password": "fkjfmsdf123"
}```

```Tokens``` = ```{
    "access": "tf;slfk;dsf",
    "refresh": "fdlsknrepkv"
}```

Как будет проходить процесс аутентификации в приложениях, использующих этот сервис?
 1) Пользователь регистрируется в сервисе
 2) Пользователь получает два токена - рефреш-токен и токен доступа
 3) При попытке получить доступ к защищенным данным, сервис проверяет токен доступа на
    валидность (просрочен или не прошел проверку хэша)
     4.1) Если пользователь отправил хороший токен, то пропускаем его
     4.2) Если токен просрочен, пытаемся получить новый токен от нашего сервиса и заменяем его
       в куках пользователя
     4.3) Если токен просрочен и мы не смогли получить новый по рефрешу, то отправляем
       пользователя на страницу авторизации

 Как происходит защита от кражи токенов?

 Токены доступа живут очень мало времени, в то время как рефреш-токены живут очень долго.

 Выданные рефреш-токены хранятся в базе сервиса аутентификации и должны быть использованы только
 один раз.

 Если утек токен доступа, то через короткое время он станет невалидным, однако если
 утек рефреш-токен, то при его повторном использовании все рефреш-токены данного пользователя
 будут удалены из базы. При этом сервис вернет время, в момент которого произошла попытка
 использования утекшего токена - его можно будет использовать для определения невалидных
 токенов, так как время их выписки будет меньше полученного времени