Exemplo de JWT Go

Aplicativo de exemplo que implementa autenticação baseada em JWT. Leia a postagem do blog aqui

Para executar este aplicativo, crie e execute o binário Go:

go build
./jwt-go-example

Agora, usando qualquer cliente HTTP com suporte para cookies (como Postman ou seu navegador da Web), faça uma solicitação de login com as credenciais apropriadas:

POST http://localhost:8000/signin

{"username":"user1","password":"password1"}

Agora você pode tentar acessar a rota de boas-vindas do mesmo cliente para obter a mensagem de boas-vindas:

GET http://localhost:8000/welcome

Acesse a rota de atualização e inspecione os cookies dos clientes para ver o novo valor do tokencookie:

POST http://localhost:8000/refresh
