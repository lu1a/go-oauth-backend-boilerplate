package db

import (
	"fmt"

	"github.com/jmoiron/sqlx"
)

func GetAccountBySession(authDB *sqlx.DB, sessionToken string) (account Account, err error) {
	query := `
		SELECT account.* FROM account
		JOIN session ON account.account_id = session.account_id
		WHERE session.session_token = $1
	`

	err = authDB.Get(&account, query, sessionToken)
	if err != nil {
		return account, err
	}

	return account, nil
}

func UpsertAccountViaGitHub(authDB *sqlx.DB, accessToken, sessionToken string, gitHubUser GitHubAccountProfile) (err error) {
	// Check if gitHubUser exists
	var count int
	err = authDB.Get(&count, "SELECT COUNT(*) FROM github_account_profile WHERE user_profile_id = $1", gitHubUser.UserProfileID)
	if err != nil {
		return err
	}

	// If it does, create a new session for the account
	if count > 0 {
		fmt.Printf("Record with ID %d exists.\n", gitHubUser.UserProfileID)

		var sessionWithThisTokenCount int
		err = authDB.Get(&sessionWithThisTokenCount, "SELECT COUNT(*) FROM session WHERE session_token = $1", sessionToken)
		if err != nil {
			return err
		} else if sessionWithThisTokenCount > 0 {
			return nil
		}

		_, err = authDB.Exec("INSERT INTO session (session_token, account_id, github_account_profile_id) VALUES($1, $2, $3)", sessionToken, gitHubUser.AccountID, gitHubUser.ProfileID)
		if err != nil {
			return err
		}

		return nil
	}

	// if it doesn't, create a new account, create a new gitHubUser, then create a new session for the account
	fmt.Printf("Record with ID %d does not exist.\n", gitHubUser.UserProfileID)

	var accountID int
	err = authDB.QueryRow("INSERT INTO account (name, email, location) VALUES($1, $2, $3) RETURNING account_id", gitHubUser.Name, gitHubUser.Email, gitHubUser.Location).Scan(&accountID)
	if err != nil {
		return err
	}
	gitHubUser.AccountID = accountID

	gitHubAccountProfileInsertQuery := `
		INSERT INTO github_account_profile (
			profile_id,
			account_id,
			user_profile_id,
			avatar_url,
			bio,
			blog,
			company,
			created_at,
			email,
			events_url,
			followers,
			followers_url,
			following,
			following_url,
			gists_url,
			gravatar_id,
			hireable,
			html_url,
			location,
			login,
			name,
			node_id,
			organizations_url,
			public_gists,
			public_repos,
			received_events_url,
			repos_url,
			site_admin,
			starred_url,
			subscriptions_url,
			twitter_username,
			user_type,
			updated_at,
			url
		) VALUES (
			:profile_id,
			:account_id,
			:user_profile_id,
			:avatar_url,
			:bio,
			:blog,
			:company,
			:created_at,
			:email,
			:events_url,
			:followers,
			:followers_url,
			:following,
			:following_url,
			:gists_url,
			:gravatar_id,
			:hireable,
			:html_url,
			:location,
			:login,
			:name,
			:node_id,
			:organizations_url,
			:public_gists,
			:public_repos,
			:received_events_url,
			:repos_url,
			:site_admin,
			:starred_url,
			:subscriptions_url,
			:twitter_username,
			:user_type,
			:updated_at,
			:url
		)
	`
	_, err = authDB.NamedExec(gitHubAccountProfileInsertQuery, gitHubUser)
	if err != nil {
		return err
	}
	_, err = authDB.Exec("INSERT INTO session (session_token, account_id, github_account_profile_id) VALUES($1, $2, $3)", sessionToken, gitHubUser.AccountID, gitHubUser.ProfileID)
	if err != nil {
		return err
	}

	return nil
}
