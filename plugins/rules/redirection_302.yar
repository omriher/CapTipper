rule rediction_302
{
        meta:
               description = "302 Redirection detection rule"
               author = "madwind@kisec.com"

        strings:
               $a = "<title>302 Found</title>"
               $b = "<p>The document has moved"

        condition:
               all of them
}