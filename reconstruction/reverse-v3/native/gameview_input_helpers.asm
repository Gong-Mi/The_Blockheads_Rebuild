
/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so:     file format elf32-littlearm


Disassembly of section .text:

004bdaac <_ZN7Vector2cvPfEv>:
  4bdaac:	e24dd004 	sub	sp, sp, #4
  4bdab0:	e58d0000 	str	r0, [sp]
  4bdab4:	e59d0000 	ldr	r0, [sp]
  4bdab8:	e28dd004 	add	sp, sp, #4
  4bdabc:	e12fff1e 	bx	lr

/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so:     file format elf32-littlearm


Disassembly of section .text:

004d0368 <_ZN7Vector2mlEf>:
  4d0368:	e92d4800 	push	{fp, lr}
  4d036c:	e1a0b00d 	mov	fp, sp
  4d0370:	e24dd010 	sub	sp, sp, #16
  4d0374:	ee002a10 	vmov	s0, r2
  4d0378:	e50b1004 	str	r1, [fp, #-4]
  4d037c:	ed8d0a02 	vstr	s0, [sp, #8]
  4d0380:	e51b1004 	ldr	r1, [fp, #-4]
  4d0384:	e58d1004 	str	r1, [sp, #4]
  4d0388:	e59d1004 	ldr	r1, [sp, #4]
  4d038c:	ed910a00 	vldr	s0, [r1]
  4d0390:	ed9d1a02 	vldr	s2, [sp, #8]
  4d0394:	ee200a01 	vmul.f32	s0, s0, s2
  4d0398:	e59d1004 	ldr	r1, [sp, #4]
  4d039c:	ed911a01 	vldr	s2, [r1, #4]
  4d03a0:	ed9d2a02 	vldr	s4, [sp, #8]
  4d03a4:	ee211a02 	vmul.f32	s2, s2, s4
  4d03a8:	ee101a10 	vmov	r1, s0
  4d03ac:	ee112a10 	vmov	r2, s2
  4d03b0:	eb000032 	bl	4d0480 <_ZN7Vector2C2Eff>
  4d03b4:	e58d0000 	str	r0, [sp]
  4d03b8:	e1a0d00b 	mov	sp, fp
  4d03bc:	e8bd8800 	pop	{fp, pc}

004d03c0 <_ZN7Vector2dvEf>:
  4d03c0:	e92d4800 	push	{fp, lr}
  4d03c4:	e1a0b00d 	mov	fp, sp
  4d03c8:	e24dd010 	sub	sp, sp, #16
  4d03cc:	ee002a10 	vmov	s0, r2
  4d03d0:	e50b1004 	str	r1, [fp, #-4]
  4d03d4:	ed8d0a02 	vstr	s0, [sp, #8]
  4d03d8:	e51b1004 	ldr	r1, [fp, #-4]
  4d03dc:	e58d1004 	str	r1, [sp, #4]
  4d03e0:	e59d1004 	ldr	r1, [sp, #4]
  4d03e4:	ed910a00 	vldr	s0, [r1]
  4d03e8:	ed9d1a02 	vldr	s2, [sp, #8]
  4d03ec:	ee800a01 	vdiv.f32	s0, s0, s2
  4d03f0:	e59d1004 	ldr	r1, [sp, #4]
  4d03f4:	ed911a01 	vldr	s2, [r1, #4]
  4d03f8:	ed9d2a02 	vldr	s4, [sp, #8]
  4d03fc:	ee811a02 	vdiv.f32	s2, s2, s4
  4d0400:	ee101a10 	vmov	r1, s0
  4d0404:	ee112a10 	vmov	r2, s2
  4d0408:	eb00001c 	bl	4d0480 <_ZN7Vector2C2Eff>
  4d040c:	e58d0000 	str	r0, [sp]
  4d0410:	e1a0d00b 	mov	sp, fp
  4d0414:	e8bd8800 	pop	{fp, pc}

004d0418 <_ZN7Vector2plES_>:
  4d0418:	e92d4800 	push	{fp, lr}
  4d041c:	e1a0b00d 	mov	fp, sp
  4d0420:	e24dd018 	sub	sp, sp, #24
  4d0424:	e24bc008 	sub	ip, fp, #8
  4d0428:	e50b2008 	str	r2, [fp, #-8]
  4d042c:	e50b3004 	str	r3, [fp, #-4]
  4d0430:	e58d100c 	str	r1, [sp, #12]
  4d0434:	e59d100c 	ldr	r1, [sp, #12]
  4d0438:	e58d1008 	str	r1, [sp, #8]
  4d043c:	e58dc004 	str	ip, [sp, #4]
  4d0440:	e59d1008 	ldr	r1, [sp, #8]
  4d0444:	ed910a00 	vldr	s0, [r1]
  4d0448:	e59d1004 	ldr	r1, [sp, #4]
  4d044c:	ed911a00 	vldr	s2, [r1]
  4d0450:	ee300a01 	vadd.f32	s0, s0, s2
  4d0454:	e59d1008 	ldr	r1, [sp, #8]
  4d0458:	ed911a01 	vldr	s2, [r1, #4]
  4d045c:	e59d1004 	ldr	r1, [sp, #4]
  4d0460:	ed912a01 	vldr	s4, [r1, #4]
  4d0464:	ee311a02 	vadd.f32	s2, s2, s4
  4d0468:	ee101a10 	vmov	r1, s0
  4d046c:	ee112a10 	vmov	r2, s2
  4d0470:	eb000002 	bl	4d0480 <_ZN7Vector2C2Eff>
  4d0474:	e58d0000 	str	r0, [sp]
  4d0478:	e1a0d00b 	mov	sp, fp
  4d047c:	e8bd8800 	pop	{fp, pc}

004d0480 <_ZN7Vector2C2Eff>:
  4d0480:	e24dd00c 	sub	sp, sp, #12
  4d0484:	ee002a10 	vmov	s0, r2
  4d0488:	ee011a10 	vmov	s2, r1
  4d048c:	e58d0008 	str	r0, [sp, #8]
  4d0490:	ed8d1a01 	vstr	s2, [sp, #4]
  4d0494:	ed8d0a00 	vstr	s0, [sp]
  4d0498:	e59d0008 	ldr	r0, [sp, #8]
  4d049c:	ed9d0a01 	vldr	s0, [sp, #4]
  4d04a0:	ed800a00 	vstr	s0, [r0]
  4d04a4:	ed9d0a00 	vldr	s0, [sp]
  4d04a8:	ed800a01 	vstr	s0, [r0, #4]
  4d04ac:	e28dd00c 	add	sp, sp, #12
  4d04b0:	e12fff1e 	bx	lr

004d04b4 <_ZN7Vector2miES_>:
  4d04b4:	e92d4800 	push	{fp, lr}
  4d04b8:	e1a0b00d 	mov	fp, sp
  4d04bc:	e24dd018 	sub	sp, sp, #24
  4d04c0:	e24bc008 	sub	ip, fp, #8
  4d04c4:	e50b2008 	str	r2, [fp, #-8]
  4d04c8:	e50b3004 	str	r3, [fp, #-4]
  4d04cc:	e58d100c 	str	r1, [sp, #12]
  4d04d0:	e59d100c 	ldr	r1, [sp, #12]
  4d04d4:	e58d1008 	str	r1, [sp, #8]
  4d04d8:	e58dc004 	str	ip, [sp, #4]
  4d04dc:	e59d1008 	ldr	r1, [sp, #8]
  4d04e0:	ed910a00 	vldr	s0, [r1]
  4d04e4:	e59d1004 	ldr	r1, [sp, #4]
  4d04e8:	ed911a00 	vldr	s2, [r1]
  4d04ec:	ee300a41 	vsub.f32	s0, s0, s2
  4d04f0:	e59d1008 	ldr	r1, [sp, #8]
  4d04f4:	ed911a01 	vldr	s2, [r1, #4]
  4d04f8:	e59d1004 	ldr	r1, [sp, #4]
  4d04fc:	ed912a01 	vldr	s4, [r1, #4]
  4d0500:	ee311a42 	vsub.f32	s2, s2, s4
  4d0504:	ee101a10 	vmov	r1, s0
  4d0508:	ee112a10 	vmov	r2, s2
  4d050c:	ebffffdb 	bl	4d0480 <_ZN7Vector2C2Eff>
  4d0510:	e58d0000 	str	r0, [sp]
  4d0514:	e1a0d00b 	mov	sp, fp
  4d0518:	e8bd8800 	pop	{fp, pc}
