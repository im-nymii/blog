---
layout: post
title: "My pretty tiny Write-Up for 0xFun !"
date: 2026-03-08
tags: [hacking, ctf, pwn, web, 0xFun, sqli]
author: Nymii
description: "a writeup of the 0xFun CTF challenges i did. mostly web stuff with some sql injection."
---

## 0xFun CTF - Mini Hacker's adventure !

finished the 0xFun CTF recently. didn't get to all the challenges, wish i had more time for them but the ones i solved were solid. here's the writeup of the web challenge i managed to complete.

## Tony's Tools - SQL Injection & Session Hijacking

this was the first web challenge i worked on. the security... well, let's say it had some interesting design choices.

### finding the hints

started by checking robots.txt (the classic move):

![robots.txt hints](/blog/assets/img/0xfun/web-chall/image.png)

three hints scattered around like breadcrumbs and honestly, they were pretty straightforward:

![secret hints](/blog/assets/img/0xfun/web-chall/image 1.png)

the hints pointed toward SQL injection, weak passwords, and session manipulation. clear direction.

### the vulnerable search parameter

Tony's Tools was a simple store interface. the search function takes user input and passes it directly to the database without sanitization:

![Tony's Tools search page](/blog/assets/img/0xfun/web-chall/image 2.png)

classic SQL injection. time to enumerate the database.

### sqlmap goes brrrr

running sqlmap against the vulnerable `item` parameter:

```
sqlmap http://chall.0xfun.org:64569/search?item=test --dbms=sqlite --tables
```

and boom, database structure revealed:

![sqlmap output](/blog/assets/img/0xfun/web-chall/image 3.png)

the Users table was sitting right there asking to be dumped. let's see what's inside:

```
sqlmap http://chall.0xfun.org:64569/search?item=caca --dbms=sqlite -T Users --dump
```

![Users table dump](/blog/assets/img/0xfun/web-chall/image 4.png)

got two users:
- **Admin** with a salted hash (kinda useless)
- **Jerry** with a hash: `0$9a00192592d5644bc0caad7203f98b506332e2cf7abb35d684ea9bf7c18f08`

the Jerry hash cracked quickly with the default wordlist. password was `iqaz2wsx`. not great.

### logging in as Jerry

logged in with those credentials:

![Jerry's login](/blog/assets/img/0xfun/web-chall/image 5.png)

got access to the dashboard. now the interesting part:

### session hijacking via cookies

after logging in, i checked the cookies in dev tools. the session cookie format was... interesting. it directly exposed the userID:

![session cookie](/blog/assets/img/0xfun/web-chall/image 6.png)

i took Jerry's session cookie and manually changed the `userID` from `2` to `1` (to access the admin profile). then i navigated to `/user` and...

### the flag

![admin profile with flag](/blog/assets/img/0xfun/web-chall/image 7.png)

there it was! the flag sitting on the admin profile !

## thoughts

this CTF was well-designed. the challenges felt balanced - not trivial, but also not impossible if you knew what you were doing. would've liked to have more time for the other challenges. there were some pwn and crypto problems that looked interesting but i ran out of time.

solid CTF overall. looking forward to the next one. 

> "big thanks to Tony for the cookie recipe - the session one was delicious" — me