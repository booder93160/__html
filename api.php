<?php
function sanitize($str)
{
    return str_replace("<", "&lt;", $str);
}

function req_db($req, $params = [])
{
    $db = new SQLite3("./truc.db");

    $stmt = $db->prepare($req);

    // Liaison des paramètres
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value);
    }

    $results = $stmt->execute();
    return $results->fetchArray();
}

$req = $_SERVER["REQUEST_URI"];

header("Content-Type: application/json");
$username = htmlspecialchars($_POST["username"]);
$password = htmlspecialchars($_POST["password"]);
$toret = array();

if ($req == "/api/calcul/")
{
    if (isset($_POST["calcul"]))
    {
         // Récupération de l'adresse IP du client
       if (isset($_SERVER["HTTP_X_FORWARDED_FOR"]) && filter_var($_SERVER["HTTP_X_FORWARDED_FOR"], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $cip = $_SERVER["HTTP_X_FORWARDED_FOR"];
     } else {
        $cip = $_SERVER["REMOTE_ADDR"];
      }

        // Insertion du calcul dans la base de données
        req_db("INSERT INTO calculs(ip_addr, user_agent, calcul) VALUES(:ip, :user_agent, :calcul);", [
            ':ip' => $cip,
            ':user_agent' => htmlspecialchars($_SERVER["HTTP_USER_AGENT"]),
            ':calcul' => str_replace("'", "", $_POST["calcul"])
        ]);

        // Évaluation du calcul
        try
        {
            eval('$toret["result"] = ' . $_POST["calcul"] . ';');
        }
        catch (ParseError $e)
        {
            $toret["result"] = "ERROR";
        }
    }
}

if ($req == "/api/user/update/")
{
    if (isset($_POST["username"]))
    {
        // // Vérification des autorisations de mise à jour
        // if ((md5($_POST["username"]) == $_COOKIE["JSESSID"]) || ($_SESSION["CONNECTED"] == 2))
        // {
            // Mise à jour du mot de passe si spécifié
            if (isset($_POST["password"])) $toret = req_db("UPDATE users SET password = :password WHERE username = :username;", [
                ':password' => $_POST["password"],
                ':username' => $_POST["username"]
            ]);
            // // SUPPRESSION DU CODE SINON ON PEUT PASSER ADMIN EN CHANGEANT LA VALEUR DE LA VARIABLE
            // if (isset($_POST["admin"])) $toret = req_db("UPDATE users SET admin = :admin WHERE username = :username;", [
            //     ':admin' => $_POST["admin"],
            //     ':username' => $_POST["username"]
            // ]);
        // }
    }
}

printf(json_encode($toret));
?>
