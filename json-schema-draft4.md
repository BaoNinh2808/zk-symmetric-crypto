
# JSON DRAFT 4

https://www.learnjsonschema.com/draft4/

### `type` ==> Assertion | any

- **ref**: https://www.learnjsonschema.com/draft4/validation/type/

- **validate**: Validation succeeds if the type of the `instance` matches the type represented by the given type, or matches at least one of the given types.

- **default**: [ "null", "boolean", "object", "array", "number", "string" ]
    ==> all value is satisfy

- **example**: 
```json
    "type" : "number"
```


### `enum` ==> Assertion | any

- **ref**: https://www.learnjsonschema.com/draft4/validation/enum/

- **validate**: Validation succeeds if the `instance` is equal to one of the elements in this keyword’s array value.

- **default**: None ==> all instance is satisfy this constrain

(if `enum` is set it must be a non-empty array)

- **example**: 
```json
    "enum" : ["a string", 43, null]
```

### `multipleOf`==> Assertion | Number

- **ref**: https://www.learnjsonschema.com/draft4/validation/multipleof/

- The value of "multipleOf" MUST be a JSON number. This number MUST be strictly greater than 0.

- **validate**: A **numeric** `instance` is valid only if division by this keyword’s value results in an integer.

- **default**: 1 ==> all interger value is satisfy

- **example**: 
```json
    "multipleOf" : 2
```
==> even number (and > 0)

-**NOTE**: not affect another type

### `maximum` ==> Assertion | Number


- **ref**: https://www.learnjsonschema.com/draft4/validation/maximum/

- The value of "maximum" MUST be a JSON number.

- **validate**: Validation succeeds if the **numeric** `instance` is less than or less than or equal to the given number, depending on the value of exclusiveMaximum, if any

- **default**: None ==> all interger value is satisfy

- **example**: 
```json
    "maximum" : 100
```
==> value <= 100

-**NOTE**: not affect another type

### `exclusiveMaximum` ==> Assertion | Number


- **ref**: https://www.learnjsonschema.com/draft4/validation/exclusivemaximum/

- The value of "maximum" MUST be a JSON number. The value of "exclusiveMaximum" MUST be a **boolean**. 

- **validate**: Validation succeeds if the numeric instance is less than the given number (in `maximum`).

- **default**: false ==> all number if <= maximum is satify 

- **example**: 
```json
    "maximum" : 100,
    "exclusiveMaximum" : true
```
==> value < 100

-**NOTE**: 
    + not affect another type
    + note that if `exclusiveMaximum` appear, **MUST** have `maximum` 

### `minimum` ==> Assertion | Number

- **ref**: https://www.learnjsonschema.com/draft4/validation/minimum/

- The value of "minimum" MUST be a JSON number.

- **validate**: Validation succeeds if the **numeric** `instance` is greater than or greater than or equal to the given number, depending on the value of `exclusiveMinimum`, if any

- **default**: None ==> all interger value is satisfy

- **example**: 
```json
    "minimum" : 1
```
==> value >= 1

-**NOTE**: not affect another type


### `exclusiveMinimum` ==> Assertion | Number


- **ref**: https://www.learnjsonschema.com/draft4/validation/exclusiveminimum/

- The value of "minimum" MUST be a JSON number. The value of "exclusiveMinimum" MUST be a **boolean**. 

- **validate**: Validation succeeds if the numeric instance is greater than the given number (in `minimum`).

- **default**: false ==> all number if >= minimum is satify 

- **example**: 
```json
    "minimum" : 1,
    "exclusiveMinimum" : true
```
==> value > 1

-**NOTE**: 
    + not affect another type
    + note that if `exclusiveMinimum` appear, **MUST** have `minimum` 


### `maxLength` ==> Assertion | String
 
- **ref**: https://www.learnjsonschema.com/draft4/validation/maxlength/

- The value of this keyword MUST be an integer. This integer MUST be greater than, or equal to, 0. 

- **validate**: A string instance is valid against this keyword if its length is less than, or equal to, the value of this keyword.

(The length of a string instance is defined as the number of its characters)

- **default**: None ==> all string is satify 

- **example**: 
```json
    "maxLength" : 10
```

-**NOTE**: 
    + not affect another type


### `minLength`==> Assertion | String

- **ref**: https://www.learnjsonschema.com/draft4/validation/minlength/

- The value of this keyword MUST be an integer. This integer MUST be greater than, or equal to, 0. 

- **validate**: A string instance is valid against this keyword if its length is greater than, or equal to, the value of this keyword.

(The length of a string instance is defined as the number of its characters)

- **default**: 0 ==> all string is satify 

- **example**: 
```json
    "minLength" : 1
```

-**NOTE**: 
    + not affect another type

### `pattern` ==> Assertion | String

- **ref**: https://www.learnjsonschema.com/draft4/validation/pattern/

- The value of this keyword MUST be a string. This string SHOULD be a valid regular expression, according to the ECMA 262 regular expression dialect.

- **validate**: A string instance is considered valid if the regular expression matches the instance successfully.

(The length of a string instance is defined as the number of its characters)

- **default**: ".*" ==> all string is satify 

- **example**: 
```json
    "pattern" : "*[0-9]"
```

==> only accept number

-**NOTE**: 
    + not affect another type


### `items` ==> Applicator | Array


- **ref**: https://www.learnjsonschema.com/draft4/validation/items/

- The value of "items" MUST be either an object or an array. If it is an object, this object MUST be a valid JSON Schema. If it is an array, items of this array MUST be objects, and each of these objects MUST be a valid JSON Schema. 

- **validate**: If set to a schema, validation succeeds if each element of the instance validates against it, otherwise validation succeeds if each element of the instance validates against the schema at the same position, if any

- **default**: {} ==> all array is satify 

- **example**: 
```json
    "items" : {"type" : "integer"}
```

==> only accept number

-**NOTE**: 
    + not affect another type


### `additionalItems` ==> Applicator | Array

- **ref**: https://www.learnjsonschema.com/draft4/validation/additionalitems/

- **validate**: If items is set to an array of schemas, validation succeeds if each element of the instance not covered by it validates against this schema. If set to false, no additional items are allowed in the array instance.

- **default**: {} ==> all array is satify 

- **example**: 
```json
    "items" : {"type" : "integer"}
    "aditionalItems" : false
```

==> only accept number


### `maxItems` ==> Assertion | Array


- **ref**: https://www.learnjsonschema.com/draft4/validation/maxitems/

- This keyword must be set to a zero or positive integer

- **validate**: An array instance is valid if its size is less than, or equal to, the value of this keyword.

- **default**: None ==> all array is satify 

- **example**: 
```json
    "maxItems" : 5
```

-**NOTE**: 
    + not affect another type


### `minItems` ==> Assertion | Array

- **ref**: https://www.learnjsonschema.com/draft4/validation/minitems/

- This keyword must be set to a zero or positive integer

- **validate**: An array instance is valid if its size is greater than, or equal to, the value of this keyword.

- **default**: None ==> all array is satify 

- **example**: 
```json
    "minItems" : 5
```

-**NOTE**: 
    + not affect another type


### `uniqueItems` ==> Assertion | Array

- **ref**: https://www.learnjsonschema.com/draft4/validation/uniqueitems/

- This keyword must be set to a boolean value

- **validate**: If this keyword is set to the boolean value true, the instance validates successfully if all of its elements are unique.

- **default**: false ==> all array is satify 

- **example**: 
```json
    "uniqueItems" : true
```

-**NOTE**: 
    + not affect another type


### `maxProperties` ==> Assertion | Object


- **ref**: https://www.learnjsonschema.com/draft4/validation/maxproperties/

- This keyword must be set to a zero or positive integer

- **validate**: An object instance is valid if its number of properties is less than, or equal to, the value of this keyword.

- **default**: None ==> all array is satify 

- **example**: 
```json
    "maxProperties" : 10
```

-**NOTE**: 
    + not affect another type


### `minProperties` ==> Assertion | Object

### `required` ==> Assertion | Object

### `properties` ==> Apllicator | Object

### `patternProperties` ==> Apllicator | Object

### `additionalProperties` ==> Apllicator | Object

### `dependencies` ==> Assertion | Object

### `allOf` ==> Apllicator | Any

### `anyOf` ==> Apllicator | Any

### `oneOf` ==> Apllicator | Any

### `not` ==> Apllicator | Any

### `format` ==> Anotation | String

### `definitions` ==> Reserved Location | Any

### `title` ==> Anotation | String

### `description` ==> Anotation | String

### `default` ==> Anotation | String
