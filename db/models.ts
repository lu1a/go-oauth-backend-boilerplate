export type Account = {
    account_id: number;
    name: string;
    email?: string | null;
    location?: string | null;
    avatar_url?: string | null;
}

export type GitHubAccountProfile = {
    profile_id: number;
    account_id: number;
    user_profile_id: number;
    avatar_url: string;
    bio?: string | null;
    blog: string;
    company: string;
    created_at: string; // Use string for representing time, adjust as needed
    email?: string | null;
    events_url: string;
    followers: number;
    followers_url: string;
    following: number;
    following_url: string;
    gists_url: string;
    gravatar_id: string;
    hireable?: boolean | null;
    html_url: string;
    location: string;
    login: string;
    name: string;
    node_id: string;
    organizations_url: string;
    public_gists: number;
    public_repos: number;
    received_events_url: string;
    repos_url: string;
    site_admin: boolean;
    starred_url: string;
    subscriptions_url: string;
    twitter_username?: string | null;
    user_type: string;
    updated_at: string; // Use string for representing time, adjust as needed
    url: string;
};
  
export type Session = {
    session_id: number;
    session_token: string;
    account_id: number;
    github_account_profile_id: number;
};