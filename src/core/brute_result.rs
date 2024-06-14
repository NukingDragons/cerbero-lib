/// Holds the possible results when running the `brute` function
pub enum BruteResult
{
	ValidPair(String, String),
	ValidUser(String),
	InvalidUser(String),
	ExpiredPassword(String, String),
	BlockedUser(String),
}
