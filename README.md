# supabase-go

Unofficial [Supabase](https://supabase.io) client for Go. It is an amalgamation of all the libraries similar to the [official Supabase client](https://supabase.io/docs/reference/javascript/supabase-client).

## Installation

```
go get github.com/geffersonFerraz/supabase-go
```

## Usage

Replace the `<SUPABASE-URL>` and `<SUPABASE-URL>` placeholders with values from `https://supabase.com/dashboard/project/YOUR_PROJECT/settings/api`

### Authenticate

```go
package main
import (
    supa "github.com/geffersonFerraz/supabase-go"
    "fmt"
    "context"
)

func main() {
  supabaseUrl := "<SUPABASE-URL>"
  supabaseKey := "<SUPABASE-KEY>"
  supabase := supa.CreateClient(supabaseUrl, supabaseKey)

  ctx := context.Background()
  user, err := supabase.Auth.SignUp(ctx, supa.UserCredentials{
    Email:    "example@example.com",
    Password: "password",
  })
  if err != nil {
    panic(err)
  }

  fmt.Println(user)
}
```

### Sign-In

```go
package main
import (
    supa "github.com/geffersonFerraz/supabase-go"
    "fmt"
    "context"
)

func main() {
  supabaseUrl := "<SUPABASE-URL>"
  supabaseKey := "<SUPABASE-KEY>"
  supabase := supa.CreateClient(supabaseUrl, supabaseKey)

  ctx := context.Background()
  user, err := supabase.Auth.SignIn(ctx, supa.UserCredentials{
    Email:    "example@example.com",
    Password: "password",
  })
  if err != nil {
    panic(err)
  }

  fmt.Println(user)
}
```

### Insert

```go
package main
import (
    supa "github.com/geffersonFerraz/supabase-go"
    "fmt"
)

type Country struct {
  ID      int    `json:"id"`
  Name    string `json:"name"`
  Capital string `json:"capital"`
}

func main() {
  supabaseUrl := "<SUPABASE-URL>"
  supabaseKey := "<SUPABASE-KEY>"
  supabase := supa.CreateClient(supabaseUrl, supabaseKey)

  row := Country{
    ID:      5,
    Name:    "Germany",
    Capital: "Berlin",
  }

  var results []Country
  err := supabase.DB.From("countries").Insert(row).Execute(&results)
  if err != nil {
    panic(err)
  }

  fmt.Println(results) // Inserted rows
}
```

### Select

```go
package main
import (
    supa "github.com/geffersonFerraz/supabase-go"
    "fmt"
)

func main() {
  supabaseUrl := "<SUPABASE-URL>"
  supabaseKey := "<SUPABASE-KEY>"
  supabase := supa.CreateClient(supabaseUrl, supabaseKey)

  var results map[string]interface{}
  err := supabase.DB.From("countries").Select("*").Single().Execute(&results)
  if err != nil {
    panic(err)
  }

  fmt.Println(results) // Selected rows
}
```

### Update

```go
package main
import (
    supa "github.com/geffersonFerraz/supabase-go"
    "fmt"
)

type Country struct {
  Name    string `json:"name"`
  Capital string `json:"capital"`
}

func main() {
  supabaseUrl := "<SUPABASE-URL>"
  supabaseKey := "<SUPABASE-KEY>"
  supabase := supa.CreateClient(supabaseUrl, supabaseKey)

  row := Country{
    Name:    "France",
    Capital: "Paris",
  }

  var results map[string]interface{}
  err := supabase.DB.From("countries").Update(row).Eq("id", "5").Execute(&results)
  if err != nil {
    panic(err)
  }

  fmt.Println(results) // Updated rows
}
```

### Delete

```go
package main
import (
    supa "github.com/geffersonFerraz/supabase-go"
    "fmt"
)

func main() {
  supabaseUrl := "<SUPABASE-URL>"
  supabaseKey := "<SUPABASE-KEY>"
  supabase := supa.CreateClient(supabaseUrl, supabaseKey)

  var results map[string]interface{}
  err := supabase.DB.From("countries").Delete().Eq("name", "France").Execute(&results)
  if err != nil {
    panic(err)
  }

  fmt.Println(results) // Empty - nothing returned from delete
}
```

### Invite user by email

```go
package main
import (
    supa "github.com/geffersonFerraz/supabase-go"
    "fmt"
    "context"
)

func main() {
  supabaseUrl := "<SUPABASE-URL>"
  supabaseKey := "<SUPABASE-KEY>"
  supabase := supa.CreateClient(supabaseUrl, supabaseKey)

  ctx := context.Background()
  user, err := supabase.Auth.InviteUserByEmail(ctx, email)
  if err != nil {
    panic(err)
  }

  // or if you want to setup some metadata
  data := map[string]interface{}{ "invitedBy": "someone" }
  redirectTo := "https://your_very_successful_app.com/signup"
  user, err = supabase.Auth.InviteUserByEmailWithData(ctx, email, data, redirectTo)
  if err != nil {
    panic(err)
  }

  fmt.Println(user)
}
```

# Original Creator

Supabase-go is an manual fork from @github.com/nedpals (https://github.com/nedpals/supabase-go)

