package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Cria a chave JWT usada para criar a assinatura
var jwtKey = []byte("my_secret_key")

// Manipulando o login do usuário
// A /signinrota pegará as credenciais dos usuários e fará o login deles.
//  Para simplificar, estamos armazenando as informações dos usuários como um mapa na memória em nosso
//   código
var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

// Portanto, por enquanto, existem apenas dois usuários válidos em nosso aplicativo: user1, e user2
// . Em seguida, podemos escrever o Signinmanipulador HTTP.
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// Create the Signin handler
func Signin(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Obtém a senha esperada do nosso mapa de memória
	expectedPassword, ok := users[creds.Username]
	// / Se existe uma senha para um determinado usuário
	// E, se for igual a senha que recebemos, podemos seguir em frente
	// se NÃO, retornamos um status "Não autorizado"
	if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(time.Minute * 5)
	// Cria as declarações JWT, que incluem o nome de usuário e o tempo de expiração
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// Se houver um erro na criação do JWT retorna um erro interno do servidor
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Por fim, definimos o cookie do cliente para "token" como o JWT que acabamos de gerar
	// também definimos um tempo de expiração que é o mesmo que o próprio token
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
	// Se um usuário fizer login com as credenciais corretas, esse manipulador definirá um cookie no lado do cliente com o valor JWT.
	// Uma vez que um cookie é definido em um cliente, ele é enviado junto com cada solicitação a partir de então.
	// Agora podemos escrever nosso manipulador de boas-vindas para lidar com informações específicas do usuário.
}

// Como lidar com rotas de pós-autenticação:
// Agora que todos os clientes logados têm informações de sessão armazenadas como cookies, podemos usá-las para:

// Autenticar solicitações de usuários subsequentes :
// Obter informações sobre o usuário que está fazendo a solicitação
// Vamos escrever nosso Welcomemanipulador para fazer exatamente isso:
// OBS : Para minimizar o uso indevido de um JWT,
// o tempo de expiração geralmente é mantido na ordem de alguns minutos. Normalmente,
//  o aplicativo cliente atualizaria o token em segundo plano.
func Welcome(w http.ResponseWriter, r *http.Request) {

	// Podemos obter o token de sessão dos cookies de requisições, que vêm com todas as requisições
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// Se o cookie não estiver definido, retorna um status não autorizado
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Para qualquer outro tipo de erro, retorna um status de solicitação inválido
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Obtém a string JWT do cookie
	tknStr := c.Value

	claims := &Claims{}
	// Analisa a string JWT e armazena o resultado em `claims`.
	// Observe que estamos passando a chave neste método também. Este método retornará um erro
	// se o token for inválido (se expirou de acordo com o tempo de expiração que definimos no login),
	// ou se a assinatura não corresponder
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {

		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Por fim, devolva a mensagem de boas-vindas ao usuário, junto com sua
	// nome de usuário dado no token
	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}

// Renovando seu token :
// Neste exemplo, definimos um tempo de expiração curto de cinco minutos.
// Não devemos esperar que o usuário faça login a cada cinco minutos se o token expirar.
// Para resolver isso, criaremos outra /refreshrota que pega o token anterior (que ainda é válido)
// e retorna um novo token com um tempo de expiração renovado.

func Refresh(w http.ResponseWriter, r *http.Request) {
	// (BEGIN) O código até este ponto é o mesmo da primeira parte da rota `Welcome`
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tknStr := c.Value

	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {

		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// (END) O código até este ponto é o mesmo da primeira parte da rota `Welcome`

	// Garantimos que um novo token não seja emitido até que tenha decorrido tempo suficiente
	// Neste caso, um novo token só será emitido se o antigo estiver dentro
	// 30 segundos de expiração. Caso contrário, retorne um status de solicitação inválido
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Agora, crie um novo token para o uso atual, com um tempo de expiração renovado
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Define o novo token como o cookie `token` dos usuários
	http.SetCookie(w, &http.Cookie{
		Name:    "toke",
		Value:   tokenString,
		Expires: expirationTime,
	})
}
