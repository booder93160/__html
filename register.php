<?php

 function isValidMDP($mdp)
 {
   return preg_match('/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$/', $mdp)  ;
 }

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

if (!empty($_POST["username"]) && !empty($_POST["password"]))
{
    // Récupération des valeurs des champs username et password
    $username = htmlspecialchars($_POST["username"]);
    $password = htmlspecialchars($_POST["password"]);

    // Requête pour vérifier si l'utilisateur existe déjà
    $userexist = req_db("SELECT * FROM users WHERE username = :username LIMIT 1", [
        ':username' => $username
    ]);

    if (! $userexist){

    $mpvalide=isValidMDP($password);
        if($mpvalide)
            {
                // Utilisation de la requête préparée pour insérer un nouvel utilisateur
                printf("Successfully created user. Redirecting...");
                req_db("INSERT INTO users(username, password, admin) VALUES(:username, :password, :admin)", [
                    ':username' => $username,
                    ':password' => password_hash($password,PASSWORD_BCRYPT),
                    ':admin' => 1
                ]);
             }
        else{ printf("Mp trop faible <br>
            <p style='color:red;':> Il doit être formé d'un minimum de 8 caractères </p>
            <p style='color:red;':> Au moins une lettre majuscule.</p> 
            <p style='color:red;':> Au moins une lettre minuscule.</p>
            <p style='color:red;':> Au moins un chiffre.</p> 
            <p style='color:red;':> Au moins un caractère spécial </p>");}
        }
        else{printf(" <h2> Failed creating user. Redirecting...</h2>");
        }
    }else{
        printf("Veuillez remplir tous les champs");}

?>
<script>
    window.onload = function() { setTimeout(function() { window.location.href = "/"; }, 4000); }
</script>
