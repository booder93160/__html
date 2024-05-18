<?php
function req_db($req, $params)
{
    $db = new SQLite3("./truc.db");
    $stmt = $db->prepare($req);
    
    // Liaison des paramètres
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }
    
    $results = $stmt->execute();
    $toret = $results->fetchArray();
    return $toret;
}

session_start();

if (!empty($_POST["username"]) && !empty($_POST["password"]))
{
    // Récupération des valeurs des champs username et password
    $username = htmlspecialchars($_POST["username"]);
    $password = htmlspecialchars($_POST["password"]);
    
    // Check si l'utilisateur existe. 
    $Passwrdreq = req_db("SELECT password FROM users WHERE username = :username", [
        ':username' => $username]);

        //Si aucun résultat apparait c'est que l'utilisateur n'existe pas
        if ($Passwrdreq){

            $Passwordhachedb=$Passwrdreq['password'];
            $checkPasswrd=password_verify($password,$Passwordhachedb);

            if ($checkPasswrd){
                $a = req_db("SELECT * FROM users WHERE username = :username LIMIT 1;", [
                    ':username' => $username
                ]);
                
                    if ($a)
                    {
                        printf("Successfully connected. Redirecting...");
                        $_SESSION["CONNECTED"] = $a["admin"];
                        $_SESSION["USERNAME"] = $a["username"];
                        $session_id = bin2hex(random_bytes(32));
                        setcookie("JSESSID", $session_id, time() + 3600, "/", "", false, true);
                    }
                    else
                    {
                        printf("L'utilisateur n'existe pas ou bien le mot de passe incorrect ");
                    }

            }else{
                    printf("L'utilisateur n'existe pas ou bien le mot de passe est incorrect ");}
        }else{
                printf("L'utilisateur n'existe pas ou bien le mot de passe est incorrect ");}

        }else{
    printf("Veuillez remplir tous les champs");
    }

?>
<script>
    window.onload = function() { setTimeout(function() { window.location.href = "/"; }, 2000); }
</script>