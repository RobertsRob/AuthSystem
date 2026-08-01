
## Where am I?

This is a template for your projects which uses authentication system. This project has lots of features:

- Log in, Sign up ofc
- View user, change email and password
- Forgot password
- Uses Google Auth and hCAPTCHA
- Has basic Admin page *(/admin)*
- Checking whether username is availible
- Rate limiting (in process)

## How to start?

How to use this project as a base for your much bigger project like social app or other app that requires authentication

1. Create a templete in github by pressing **Use this template**
2. Clone now your repository
3. Now you need to use .env.exapmle to create your own .env There are a lot of fields, if you dont fill all of them some features may not work.
4. Thats good, now you cimply neet do run ```docker compose up --build```
5. Your app is now runnign on `localhost:5000`
6. *(Now if you want so your CI/CD works you will need to rewrite deploying part as my server configuration most probably is different from yours. But for information on github i ahve these 4 enviromental variables DEPLOY_PATH SERVER_HOST SERVER_USER SSH_PRIVATE_KEY )*

## AI usage

Claude was used as a documentation for managing CI/CD pipelines and Flask, Claude for complex bug debbuging. ChatGPT for simple coding questions.

## More

How to back up postgres db:
docker compose exec db pg_dump -U {user} {db_name} > backup.sql


## Routes
*This part was written buy AI:*

GET  /                          → renders home page
GET  /login                     → login page (redirects to /home_user if already logged in) [?error]
GET  /signup                    → signup page (redirects to /home_user if already logged in) [?error]
GET  /home_user                 → user dashboard (requires valid access_token cookie)
GET  /logout                    → clears session + deletes access_token cookie, redirects home
GET  /settings                  → account settings page [?error, ?success]
GET  /forgot_password           → forgot password form [?error]
GET  /email_was_sent            → confirmation page after reset email sent
GET  /password_was_reset        → confirmation page after password reset

GET  /google_auth                     → kicks off Google OAuth redirect
POST /auth/google/callback             → Google OAuth callback, creates/logs in user, sets JWT cookie
POST /login_submit                     → validates captcha + credentials, sets JWT cookie  [5/min, 20/hr]
POST /signup_submit                    → validates captcha + fields, creates user, sets JWT cookie  [5/hr]

POST /send_password_reset_email        → captcha + email → generates token, emails reset link  [3/hr]
GET|POST /reset_password_link          → GET: shows reset form (?token, ?error) / POST: validates token+captcha, updates password  [10/hr]

POST /update_email                     → change email (requires current password)  [5/hr]
POST /update_password                  → change password (requires current password)  [5/hr]

GET  /api/users/check ?username=       → returns {status, exists} bool for username availability  [30/min]

GET    /admin                          → admin dashboard
GET    /admin/view_users ?offset&limit → paginated user list (limit capped at 50)
DELETE /delete_user/<int:id>           → deletes user by id
PATCH  /update_role/<int:id>           → toggles role between "user" and "admin"