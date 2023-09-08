
We can keep each term in a record as a sort key.
This would reveal how many terms a document has but nothing more.
Keeping all fields from the doc in the same set of terms would spread the frequency across multiple fields.
Each term would be associated with a bloom filter built specifically from that term key.
Queries rely on getting the least frequent term from the dict and using it to build the corresponding bloom.

We can't randomize bloom filters per doc ID though.
Well, we could but we'd have to check them all in memory.

Do devs want a high-level abstraction (like a dynamo like ORM) or do they want CS to be low-level so they can use it
how they like (ideally with the AWS SDK).
Likely the latter.


Term key must be the HMAC of the field name its value.

Example:
```
field => [bloom | source_encryption]
field#name => source_encryption(name)
index#name#<t0> => bloom(T except t0)
index#name#<t1> => bloom(T except t1)
...
index#name#<tn> => bloom(T except tn)
```

We don't need to encrypt field#name nor even the prefixes of the index names.
We could encrypt each term and use those as the key to add the deterministic term keys to the bloom filter!
The encryptions could themselves be used as hash functions for the bloom.

Querying would require a batch_get not just for the field name but for the corresponding bloom.

## What is the migration process for adding CipherStash to an existing dynamoDB?

Assuming we have a partition key and a sort key that is a string or binary, Encrypt the values that are there.
Use the sort key to store the terms.

## Dynamo would probably be a good fit for Vero.

## Mental model for this technique

It's like we are retrieving records by their ID but instead that ID is a cryptographic generator.

## OPE instead of ORE

We can take the same approach to OPE as we did for equality/DE.
OPE is insecure when its vulnerable to inference attacks.
But if every partition used its own OPE key, such inferences would be impossible.
The OPE prefix could be say 1 randomized byte.
That means range queries could be achieved by generating prefixes for all values > or < than a query term.
You'd have to randomize each of those, too! Doh.
It's actually like a query (like above) but with 256 possible query terms.
We could use a combination of bloom filter and OPE.
The bloom filters work like free-text search but with a dictionary of now only 256 possible values.
The query first loads the dict with the smallest frequency, which in this case is a numeric prefix. Say 120.
We use its count to generate some query terms, k.
If say our query is x < 175,200 then we now need to generate a bloom filter based on each k.
To that bloom filter we add the numbers 0..175 except 120.
We now have a list of tuples which each contain k and bloom filter (k, b).
We now also generate for each k, an OPE term which represents 200 encoded with the key from 120.

## Demo
* Encrypt the partition key ✅ 
* Put ✅
* Query ✅
* Get ✅
* Decryption ✅
* Bug: queries only update on the second call (I think the count is stale)
* Delete?

Stretch
* Adding a subtype? (e.g. DriversLicense) (different type but with the same PK)
* Distinguish between exact and startswith in the query method
* Error Handling
- Including if the target type cannot be deserialized
* Encrypt the dict counts


## Production Implementation

* Packaging up the crate
* Comprehensive tests
* Credential caching/lambda
* Control which attributes end up in indexes (like projections in Dynamo)
* Ability to support encrypted and plaintext attributes
* Load field configs from Vitur/Dataset (add Dict Indexer type to schema)
- How to manage changing config (encryption migrations)
- Perhaps a config fingerprint is used in the sortkey somehow (there are multiple versions of a record based on config)
* Use Blob instead of string where possible
* Lambda stream handler for compaction
* Counter contention mitigation
* Derive Macros
- Handle subtypes well (they must have the same partition key as the parent type)
* Work out why the ciphertexts are so long!
* Other data types
* "StartsWith" operator in Vitur Schema
* Conjunctive queries?
* Bulk encrypt and decrypt
* Indexers: index vs query settings to make edgegram queries possible

## Later
* How to migrate an existing table?
* Better dataset config structure (more broadly applicable)


