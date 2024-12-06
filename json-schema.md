# JSON SCHEMA

## Json schema

- formatting
- syntax
- data types
- structures & content

## Type

`instance` has 6 primitive types:

- null
- boolean: true/false
- object: json object
- array: array (of any type)
- number: any number (float, integer,...)
- string: string of unicode
- integer:

## Json Schema Documents

Json Schema Document = schema : **describle** an instance

## Keywords

5 categories:

- **identifier**: schema identifiers
- **assertion**: produce a boolean result when apply to an instance
- **annotation**: attach information to instance
- **applicator**: apply one or more subschema to an instance --> combine/modify the result
- **reserved location**: don't affect directly result, just for ensure interoperability

## Keywords for Apply subschema:

- allOf: non-empty array schema --> validate TRUE for all conditions in this array
- anyOf: non-empty array schema--> at least ONE condition can validate TRUE
- not: schema --> validate FALSE

## Conditional Keywords:

- if, then, else :
- dependentSchemas: apply to check only when the json instance have the the specific property

# JSON DRAFT 4

https://www.learnjsonschema.com/draft4/

## Keywords:

### `type`

### `enum`

### `multipleOf`

### `maximum`

### `exclusiveMaximum`

### `minimum`

### `exclusiveMinimum`

### `maxLength`

### `minLength`

### `pattern`

### `items`

### `additionalItems`

### `maxItems`

### `minItems`

### `uniqueItems`

### `maxProperties`

### `minProperties`

### `required`

### `properties`

### `patternProperties`

### `additionalProperties`

### `dependencies`

### `allOf`

### `anyOf`

### `oneOf`

### `not`

### `format`

### `definitions`

### `title`

### `description`

### `default`
