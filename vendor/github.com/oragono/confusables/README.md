# Unicode confusables

This Go library implements the `Skeleton` algorithm from Unicode TR39

See http://www.unicode.org/reports/tr39/

### Examples
```
import "github.com/mtibben/confusables"

confusables.Skeleton("𝔭𝒶ỿ𝕡𝕒ℓ")  # "paypal"
confusables.Confusable("𝔭𝒶ỿ𝕡𝕒ℓ", "paypal")  # true
```

*Note on the use of `Skeleton`, from TR39:*

> A skeleton is intended only for internal use for testing confusability of strings; the resulting text is not suitable for display to users, because it will appear to be a hodgepodge of different scripts. In particular, the result of mapping an identifier will not necessary be an identifier. Thus the confusability mappings can be used to test whether two identifiers are confusable (if their skeletons are the same), but should definitely not be used as a "normalization" of identifiers.
