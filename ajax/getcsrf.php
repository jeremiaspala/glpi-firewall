<?php
include('../../../inc/includes.php');
Session::checkLoginUser();
return new \Symfony\Component\HttpFoundation\JsonResponse([
    'token' => Session::getNewCSRFToken(),
]);
