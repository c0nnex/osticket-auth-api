<?php

namespace ApiAuth;

use AccessDenied;
use UserAuthenticationBackend;
use ClientSession;

class UserAuthBackend extends UserAuthenticationBackend 
{
    use Authenticator;

    public static $name = 'External API Authentication';
    public static $id = 'externalapi';
    private $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    public function supportsInteractiveAuthentication()
    {
        return true;
    }

    public function authenticate($username, $password)
    {
        $apiResponse = $this->getApiResponse($username, $password);
        if ($apiResponse->success) {

                    // Let's do the osTicket auth stuff!
                    // Try and find the account by their username....
                    $acct = ClientAccount::lookupByUsername($apiResponse->user->username);
                    if ($acct = ClientAccount::lookupByUsername($apiResponse->user->username)) {
                        if (($client = new ClientSession(new EndUser($acct->getUser()))) && $client->getId()) {
                            $user = $acct->getUser();
                            $oldAddress = $user->getDefaultEmailAddress();
                            $userID = $client->getId();
                            // Has their email changed?
                            if(strcasecmp($oldAddress, $apiResponse->user->user_email) != 0){
                                // Let's check if this email exists, first of all.
                                $newEmail = UserEmailModel::lookup(array("address" => $apiResponse->user->user_email));
                                if($newEmail){
                                    // Let's update the user_id for this email!
                                    $newEmail->set("user_id", $userID);
                                    $newEmail->save();
                                } else {
                                    // Let's add the new email.
                                    $newEmail = UserEmailModel::create();
                                    $newEmail->set("user_id", $userID);
                                    $newEmail->set("address", $apiResponse->user->user_email);
                                    $newEmail->save();
                                }
                                // Update the default email ID.
                                $user->set("default_email_id", $newEmail->get("id"));
                                $user->save();
                            }
                            return $client;
                        }
                    } else { // Doesn't exist, so let's make one?
                        // IF the user has previously used helpdesk to submit a ticket via email (without an account) this will sync, based on email address.
                        $client = new ClientCreateRequest($this, $apiResponse->user->username, ["email" => $apiResponse->user->user_email, "name" => $apiResponse->user->username]);
                        return $client->attemptAutoRegister();
                    }
        } elseif ($apiResponse->error) {
            return new AccessDenied($apiResponse->error);
        } else {
            return new AccessDenied('Unable to validate login.');
        }
    }

    public function renderExternalLink()
    {
        return false;
    }

    public function supportsPasswordChange()
    {
        return false;
    }

    public function supportsPasswordReset()
    {
        return false;
    }
}
