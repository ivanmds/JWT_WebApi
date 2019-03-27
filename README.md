# JWT_WebApi
exemplo simples de geração e consumo de token jwt com grant_type password e refresh_token

obter token 
  => (POST) http://localhost:60274/oauth2/token
     Header = { 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' }
     
     quando o grant_type for password
     Body = { 'username': 'teste01', 'password': '111', 'grant_type': 'password', 'client_id': '559a5aa2-9733-41b5-a272-92ecd1040ad3' } 
     
     quando o grant_type for refresh_token
     Body = { 'grant_type': 'refresh_token', 'refresh_token': '54327753-02f5-4d5d-8ebd-af5a4764d673', 'client_id': '559a5aa2-9733-41b5-a272-92ecd1040ad3' }
     
     
consuminso o token
  => (GET) http://localhost:60274/api/tests
     Header = { Authorization: 'bearer {valueToken}' }
  
