# OmniAuth for Globalize

Globalize OAuth2 Strategy for OmniAuth 1.0.

Supports the OAuth 2.0 server-side. Read the Globalize docs for more details: https://globalize.com/docs

## Installing

Add to your `Gemfile`:

```ruby
gem 'omniauth-globalize'
```

Then `bundle install`.

## Usage

`OmniAuth::Strategies::Globalize` is simply a Rack middleware. Read the OmniAuth 1.0 docs for detailed instructions: https://github.com/intridea/omniauth.

Here's a quick example, adding the middleware to a Rails app in `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :globalize, ENV['GLOBALIZE_KEY'], ENV['GLOBALIZE_SECRET']
end
```

## Configuring

You can configure several options, which you pass in to the `provider` method via a `Hash`:

* `scope`: A comma-separated list of permissions you want to request from the user. See the Globalize docs for a full list of available permissions. Default: `email`.
* `display`: The display context to show the authentication page. Options are: `web`, `desktop` and `mobile`. Default: `web`.

For example, to request `email` permission and display the authorization page in a mobile app:
 
```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :globalize, ENV['GLOBALIZE_KEY'], ENV['GLOBALIZE_SECRET'], :scope => 'email', :display => 'mobile'
end
```

If you want to set the `display` format on a per-request basis, you can just pass it to the OmniAuth request phase URL, for example: `/auth/globalize?display=popup`.

## Authentication Hash

Here's an example *Authentication Hash* available in `request.env['omniauth.auth']`:

```ruby
{
  :provider => 'globalize',
  :uid => '123',
  :info => {
    :first_name => 'Alex',
    :last_name => 'Thompson',
    :email => 'alex@sample.com',
    :name => 'Alex Thompson'
  },
  :credentials => {
    :token => 'ABCDEF...', 			# OAuth 2.0 access_token
    :expires_at => 1321747205 	# when the access token expires
  },
  :extra => {
    :user => {
      :id => '1234567',
      :name => 'Alex Thompson',
      :first_name => 'Alex',
      :last_name => 'Thompson'
    }
  }
}
```

The precise information available may depend on the permissions which you request.
