export GOOGLE_CLIENT_ID=<put your google client id here>
export GOOGLE_CLIENT_SECRET=<put your google client secret here>
export GOOGLE_REDIRECT_URI_LOGIN=http://localhost:3000/user/sso_login
export GOOGLE_REDIRECT_URI_REGISTER=http://localhost:3000/user/sso_register
export DOMAIN=localhost
export PORT=9000

if [ ! -d "./bin" ]; then
  curl -sSfL https://raw.githubusercontent.com/cosmtrek/air/master/install.sh | sh -s
fi

./bin/air
# go run .