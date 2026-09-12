
/data/data/com.termux/files/home/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so:     file format elf32-littlearm


Disassembly of section .text:

0092d1c4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15140>:
  92d1c4:	e92d4df0 	push	{r4, r5, r6, r7, r8, sl, fp, lr}
  92d1c8:	e28db018 	add	fp, sp, #24
  92d1cc:	e24dde1b 	sub	sp, sp, #432	@ 0x1b0
  92d1d0:	e59fcc80 	ldr	ip, [pc, #3200]	@ 92de58 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15dd4>
  92d1d4:	e08fc00c 	add	ip, pc, ip
  92d1d8:	ee003a10 	vmov	s0, r3
  92d1dc:	ee012a10 	vmov	s2, r2
  92d1e0:	e59b2010 	ldr	r2, [fp, #16]
  92d1e4:	e59b300c 	ldr	r3, [fp, #12]
  92d1e8:	e59be014 	ldr	lr, [fp, #20]
  92d1ec:	e59b4008 	ldr	r4, [fp, #8]
  92d1f0:	e59f5be4 	ldr	r5, [pc, #3044]	@ 92dddc <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d58>
  92d1f4:	e795500c 	ldr	r5, [r5, ip]
  92d1f8:	e59f6be0 	ldr	r6, [pc, #3040]	@ 92dde0 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d5c>
  92d1fc:	e086600c 	add	r6, r6, ip
  92d200:	e59f7bdc 	ldr	r7, [pc, #3036]	@ 92dde4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d60>
  92d204:	e797700c 	ldr	r7, [r7, ip]
  92d208:	e3008000 	movw	r8, #0
  92d20c:	e59fabd4 	ldr	sl, [pc, #3028]	@ 92dde8 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d64>
  92d210:	e79aa00c 	ldr	sl, [sl, ip]
  92d214:	e50b3038 	str	r3, [fp, #-56]	@ 0xffffffc8
  92d218:	e50b2034 	str	r2, [fp, #-52]	@ 0xffffffcc
  92d21c:	e50b003c 	str	r0, [fp, #-60]	@ 0xffffffc4
  92d220:	e50b1040 	str	r1, [fp, #-64]	@ 0xffffffc0
  92d224:	ed0b1a11 	vstr	s2, [fp, #-68]	@ 0xffffffbc
  92d228:	ed0b0a12 	vstr	s0, [fp, #-72]	@ 0xffffffb8
  92d22c:	e50b404c 	str	r4, [fp, #-76]	@ 0xffffffb4
  92d230:	e50be050 	str	lr, [fp, #-80]	@ 0xffffffb0
  92d234:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d238:	e59a1000 	ldr	r1, [sl]
  92d23c:	e0800001 	add	r0, r0, r1
  92d240:	e5c08000 	strb	r8, [r0]
  92d244:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d248:	e5971000 	ldr	r1, [r7]
  92d24c:	e0800001 	add	r0, r0, r1
  92d250:	e5900000 	ldr	r0, [r0]
  92d254:	e5961000 	ldr	r1, [r6]
  92d258:	e58dc0bc 	str	ip, [sp, #188]	@ 0xbc
  92d25c:	e12fff35 	blx	r5
  92d260:	e6af0070 	sxtb	r0, r0
  92d264:	e3500000 	cmp	r0, #0
  92d268:	0a0002d9 	beq	92ddd4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d50>
  92d26c:	e59f0b68 	ldr	r0, [pc, #2920]	@ 92dddc <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d58>
  92d270:	e59d10bc 	ldr	r1, [sp, #188]	@ 0xbc
  92d274:	e7900001 	ldr	r0, [r0, r1]
  92d278:	e1a02000 	mov	r2, r0
  92d27c:	e59f3b68 	ldr	r3, [pc, #2920]	@ 92ddec <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d68>
  92d280:	e0833001 	add	r3, r3, r1
  92d284:	e59fcb64 	ldr	ip, [pc, #2916]	@ 92ddf0 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d6c>
  92d288:	e08cc001 	add	ip, ip, r1
  92d28c:	e59feb50 	ldr	lr, [pc, #2896]	@ 92dde4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d60>
  92d290:	e79ee001 	ldr	lr, [lr, r1]
  92d294:	e51b403c 	ldr	r4, [fp, #-60]	@ 0xffffffc4
  92d298:	e59ee000 	ldr	lr, [lr]
  92d29c:	e084e00e 	add	lr, r4, lr
  92d2a0:	e59ee000 	ldr	lr, [lr]
  92d2a4:	e59c1000 	ldr	r1, [ip]
  92d2a8:	e58d00b8 	str	r0, [sp, #184]	@ 0xb8
  92d2ac:	e1a0000e 	mov	r0, lr
  92d2b0:	e59dc0b8 	ldr	ip, [sp, #184]	@ 0xb8
  92d2b4:	e58d20b4 	str	r2, [sp, #180]	@ 0xb4
  92d2b8:	e58d30b0 	str	r3, [sp, #176]	@ 0xb0
  92d2bc:	e12fff3c 	blx	ip
  92d2c0:	e59d10b0 	ldr	r1, [sp, #176]	@ 0xb0
  92d2c4:	e5911000 	ldr	r1, [r1]
  92d2c8:	e59d20b4 	ldr	r2, [sp, #180]	@ 0xb4
  92d2cc:	e12fff32 	blx	r2
  92d2d0:	e6af0070 	sxtb	r0, r0
  92d2d4:	e3500000 	cmp	r0, #0
  92d2d8:	1a0002bd 	bne	92ddd4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d50>
  92d2dc:	e59f0af8 	ldr	r0, [pc, #2808]	@ 92dddc <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d58>
  92d2e0:	e59d10bc 	ldr	r1, [sp, #188]	@ 0xbc
  92d2e4:	e7900001 	ldr	r0, [r0, r1]
  92d2e8:	e59f2b04 	ldr	r2, [pc, #2820]	@ 92ddf4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d70>
  92d2ec:	e0822001 	add	r2, r2, r1
  92d2f0:	e59f3aec 	ldr	r3, [pc, #2796]	@ 92dde4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d60>
  92d2f4:	e7933001 	ldr	r3, [r3, r1]
  92d2f8:	e51bc03c 	ldr	ip, [fp, #-60]	@ 0xffffffc4
  92d2fc:	e5933000 	ldr	r3, [r3]
  92d300:	e08c3003 	add	r3, ip, r3
  92d304:	e5933000 	ldr	r3, [r3]
  92d308:	e5921000 	ldr	r1, [r2]
  92d30c:	e58d00ac 	str	r0, [sp, #172]	@ 0xac
  92d310:	e1a00003 	mov	r0, r3
  92d314:	e59d20ac 	ldr	r2, [sp, #172]	@ 0xac
  92d318:	e12fff32 	blx	r2
  92d31c:	e6af0070 	sxtb	r0, r0
  92d320:	e3500000 	cmp	r0, #0
  92d324:	1a0002aa 	bne	92ddd4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d50>
  92d328:	e59f0aac 	ldr	r0, [pc, #2732]	@ 92dddc <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d58>
  92d32c:	e59d10bc 	ldr	r1, [sp, #188]	@ 0xbc
  92d330:	e7900001 	ldr	r0, [r0, r1]
  92d334:	e59f2abc 	ldr	r2, [pc, #2748]	@ 92ddf8 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d74>
  92d338:	e0822001 	add	r2, r2, r1
  92d33c:	e59f3aa0 	ldr	r3, [pc, #2720]	@ 92dde4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d60>
  92d340:	e7933001 	ldr	r3, [r3, r1]
  92d344:	e51bc03c 	ldr	ip, [fp, #-60]	@ 0xffffffc4
  92d348:	e5933000 	ldr	r3, [r3]
  92d34c:	e08c3003 	add	r3, ip, r3
  92d350:	e5933000 	ldr	r3, [r3]
  92d354:	e5921000 	ldr	r1, [r2]
  92d358:	e58d00a8 	str	r0, [sp, #168]	@ 0xa8
  92d35c:	e1a00003 	mov	r0, r3
  92d360:	e59d20a8 	ldr	r2, [sp, #168]	@ 0xa8
  92d364:	e12fff32 	blx	r2
  92d368:	e6af0070 	sxtb	r0, r0
  92d36c:	e3500000 	cmp	r0, #0
  92d370:	0a000297 	beq	92ddd4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d50>
  92d374:	e3000000 	movw	r0, #0
  92d378:	e59f1a5c 	ldr	r1, [pc, #2652]	@ 92dddc <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d58>
  92d37c:	e59d20bc 	ldr	r2, [sp, #188]	@ 0xbc
  92d380:	e7911002 	ldr	r1, [r1, r2]
  92d384:	e59f3a70 	ldr	r3, [pc, #2672]	@ 92ddfc <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d78>
  92d388:	e0833002 	add	r3, r3, r2
  92d38c:	e59fca50 	ldr	ip, [pc, #2640]	@ 92dde4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d60>
  92d390:	e79cc002 	ldr	ip, [ip, r2]
  92d394:	e51be03c 	ldr	lr, [fp, #-60]	@ 0xffffffc4
  92d398:	e59cc000 	ldr	ip, [ip]
  92d39c:	e08ec00c 	add	ip, lr, ip
  92d3a0:	e59cc000 	ldr	ip, [ip]
  92d3a4:	e5933000 	ldr	r3, [r3]
  92d3a8:	e58d00a4 	str	r0, [sp, #164]	@ 0xa4
  92d3ac:	e1a0000c 	mov	r0, ip
  92d3b0:	e58d10a0 	str	r1, [sp, #160]	@ 0xa0
  92d3b4:	e1a01003 	mov	r1, r3
  92d3b8:	e59d30a4 	ldr	r3, [sp, #164]	@ 0xa4
  92d3bc:	e6af2073 	sxtb	r2, r3
  92d3c0:	e59dc0a0 	ldr	ip, [sp, #160]	@ 0xa0
  92d3c4:	e12fff3c 	blx	ip
  92d3c8:	e51b004c 	ldr	r0, [fp, #-76]	@ 0xffffffb4
  92d3cc:	e3500001 	cmp	r0, #1
  92d3d0:	1a00013a 	bne	92d8c0 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x1583c>
  92d3d4:	e59f0a60 	ldr	r0, [pc, #2656]	@ 92de3c <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15db8>
  92d3d8:	e59d10bc 	ldr	r1, [sp, #188]	@ 0xbc
  92d3dc:	e7900001 	ldr	r0, [r0, r1]
  92d3e0:	e51b203c 	ldr	r2, [fp, #-60]	@ 0xffffffc4
  92d3e4:	e5900000 	ldr	r0, [r0]
  92d3e8:	e0820000 	add	r0, r2, r0
  92d3ec:	e1d000d0 	ldrsb	r0, [r0]
  92d3f0:	e3500000 	cmp	r0, #0
  92d3f4:	1a00002a 	bne	92d4a4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15420>
  92d3f8:	e24b0058 	sub	r0, fp, #88	@ 0x58
  92d3fc:	e3001000 	movw	r1, #0
  92d400:	ed9f0a26 	vldr	s0, [pc, #152]	@ 92d4a0 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x1541c>
  92d404:	e59f2a34 	ldr	r2, [pc, #2612]	@ 92de40 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15dbc>
  92d408:	e59d30bc 	ldr	r3, [sp, #188]	@ 0xbc
  92d40c:	e7922003 	ldr	r2, [r2, r3]
  92d410:	e59fc9c4 	ldr	ip, [pc, #2500]	@ 92dddc <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d58>
  92d414:	e79cc003 	ldr	ip, [ip, r3]
  92d418:	e59fea30 	ldr	lr, [pc, #2608]	@ 92de50 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15dcc>
  92d41c:	e08ee003 	add	lr, lr, r3
  92d420:	e59f49bc 	ldr	r4, [pc, #2492]	@ 92dde4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d60>
  92d424:	e7944003 	ldr	r4, [r4, r3]
  92d428:	e51b503c 	ldr	r5, [fp, #-60]	@ 0xffffffc4
  92d42c:	e5944000 	ldr	r4, [r4]
  92d430:	e0854004 	add	r4, r5, r4
  92d434:	e5944000 	ldr	r4, [r4]
  92d438:	e59ee000 	ldr	lr, [lr]
  92d43c:	e58d009c 	str	r0, [sp, #156]	@ 0x9c
  92d440:	e1a00004 	mov	r0, r4
  92d444:	e58d1098 	str	r1, [sp, #152]	@ 0x98
  92d448:	e1a0100e 	mov	r1, lr
  92d44c:	e58d2094 	str	r2, [sp, #148]	@ 0x94
  92d450:	ed8d0a24 	vstr	s0, [sp, #144]	@ 0x90
  92d454:	e12fff3c 	blx	ip
  92d458:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d45c:	e59d1094 	ldr	r1, [sp, #148]	@ 0x94
  92d460:	e5912000 	ldr	r2, [r1]
  92d464:	e0800002 	add	r0, r0, r2
  92d468:	e59d209c 	ldr	r2, [sp, #156]	@ 0x9c
  92d46c:	e58d008c 	str	r0, [sp, #140]	@ 0x8c
  92d470:	e1a00002 	mov	r0, r2
  92d474:	ed9d0a24 	vldr	s0, [sp, #144]	@ 0x90
  92d478:	ee101a10 	vmov	r1, s0
  92d47c:	ee102a10 	vmov	r2, s0
  92d480:	ebee8bfe 	bl	4d0480 <_ZN7Vector2C2Eff>
  92d484:	e51b1058 	ldr	r1, [fp, #-88]	@ 0xffffffa8
  92d488:	e59d208c 	ldr	r2, [sp, #140]	@ 0x8c
  92d48c:	e5821000 	str	r1, [r2]
  92d490:	e51b1054 	ldr	r1, [fp, #-84]	@ 0xffffffac
  92d494:	e5821004 	str	r1, [r2, #4]
  92d498:	e58d0088 	str	r0, [sp, #136]	@ 0x88
  92d49c:	ea000000 	b	92d4a4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15420>
  92d4a0:	00000000 	andeq	r0, r0, r0
  92d4a4:	e24b0060 	sub	r0, fp, #96	@ 0x60
  92d4a8:	e59f1988 	ldr	r1, [pc, #2440]	@ 92de38 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15db4>
  92d4ac:	e59d20bc 	ldr	r2, [sp, #188]	@ 0xbc
  92d4b0:	e7911002 	ldr	r1, [r1, r2]
  92d4b4:	e51b303c 	ldr	r3, [fp, #-60]	@ 0xffffffc4
  92d4b8:	e5911000 	ldr	r1, [r1]
  92d4bc:	e0831001 	add	r1, r3, r1
  92d4c0:	ed1b0a0e 	vldr	s0, [fp, #-56]	@ 0xffffffc8
  92d4c4:	ed1b1a0d 	vldr	s2, [fp, #-52]	@ 0xffffffcc
  92d4c8:	ee103a10 	vmov	r3, s0
  92d4cc:	e58d1084 	str	r1, [sp, #132]	@ 0x84
  92d4d0:	e1a01003 	mov	r1, r3
  92d4d4:	ee112a10 	vmov	r2, s2
  92d4d8:	ebee8be8 	bl	4d0480 <_ZN7Vector2C2Eff>
  92d4dc:	e59f1954 	ldr	r1, [pc, #2388]	@ 92de38 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15db4>
  92d4e0:	e59d20bc 	ldr	r2, [sp, #188]	@ 0xbc
  92d4e4:	e7911002 	ldr	r1, [r1, r2]
  92d4e8:	e59f3928 	ldr	r3, [pc, #2344]	@ 92de18 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d94>
  92d4ec:	e7933002 	ldr	r3, [r3, r2]
  92d4f0:	e51bc060 	ldr	ip, [fp, #-96]	@ 0xffffffa0
  92d4f4:	e59de084 	ldr	lr, [sp, #132]	@ 0x84
  92d4f8:	e58ec000 	str	ip, [lr]
  92d4fc:	e51bc05c 	ldr	ip, [fp, #-92]	@ 0xffffffa4
  92d500:	e58ec004 	str	ip, [lr, #4]
  92d504:	e51bc03c 	ldr	ip, [fp, #-60]	@ 0xffffffc4
  92d508:	e5933000 	ldr	r3, [r3]
  92d50c:	e08c3003 	add	r3, ip, r3
  92d510:	ed930a02 	vldr	s0, [r3, #8]
  92d514:	e51b303c 	ldr	r3, [fp, #-60]	@ 0xffffffc4
  92d518:	e5911000 	ldr	r1, [r1]
  92d51c:	e0831001 	add	r1, r3, r1
  92d520:	e58d0080 	str	r0, [sp, #128]	@ 0x80
  92d524:	e1a00001 	mov	r0, r1
  92d528:	ed8d0a1f 	vstr	s0, [sp, #124]	@ 0x7c
  92d52c:	ebee415e 	bl	4bdaac <_ZN7Vector2cvPfEv>
  92d530:	e59f1900 	ldr	r1, [pc, #2304]	@ 92de38 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15db4>
  92d534:	e59d20bc 	ldr	r2, [sp, #188]	@ 0xbc
  92d538:	e7911002 	ldr	r1, [r1, r2]
  92d53c:	e59f38d4 	ldr	r3, [pc, #2260]	@ 92de18 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d94>
  92d540:	e7933002 	ldr	r3, [r3, r2]
  92d544:	ed900a00 	vldr	s0, [r0]
  92d548:	ed9d1a1f 	vldr	s2, [sp, #124]	@ 0x7c
  92d54c:	ee300a41 	vsub.f32	s0, s0, s2
  92d550:	ed800a00 	vstr	s0, [r0]
  92d554:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d558:	e5933000 	ldr	r3, [r3]
  92d55c:	e0800003 	add	r0, r0, r3
  92d560:	ed900a03 	vldr	s0, [r0, #12]
  92d564:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d568:	e5911000 	ldr	r1, [r1]
  92d56c:	e0800001 	add	r0, r0, r1
  92d570:	ed8d0a1e 	vstr	s0, [sp, #120]	@ 0x78
  92d574:	ebee414c 	bl	4bdaac <_ZN7Vector2cvPfEv>
  92d578:	e59f18b8 	ldr	r1, [pc, #2232]	@ 92de38 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15db4>
  92d57c:	e59d20bc 	ldr	r2, [sp, #188]	@ 0xbc
  92d580:	e7911002 	ldr	r1, [r1, r2]
  92d584:	ed900a01 	vldr	s0, [r0, #4]
  92d588:	ed9d1a1e 	vldr	s2, [sp, #120]	@ 0x78
  92d58c:	ee300a41 	vsub.f32	s0, s0, s2
  92d590:	ed800a01 	vstr	s0, [r0, #4]
  92d594:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d598:	e5911000 	ldr	r1, [r1]
  92d59c:	e0800001 	add	r0, r0, r1
  92d5a0:	ebee4141 	bl	4bdaac <_ZN7Vector2cvPfEv>
  92d5a4:	e59f188c 	ldr	r1, [pc, #2188]	@ 92de38 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15db4>
  92d5a8:	e59d20bc 	ldr	r2, [sp, #188]	@ 0xbc
  92d5ac:	e7911002 	ldr	r1, [r1, r2]
  92d5b0:	ed900a01 	vldr	s0, [r0, #4]
  92d5b4:	eeb10a40 	vneg.f32	s0, s0
  92d5b8:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d5bc:	e5911000 	ldr	r1, [r1]
  92d5c0:	e0800001 	add	r0, r0, r1
  92d5c4:	ed8d0a1d 	vstr	s0, [sp, #116]	@ 0x74
  92d5c8:	ebee4137 	bl	4bdaac <_ZN7Vector2cvPfEv>
  92d5cc:	e24b1068 	sub	r1, fp, #104	@ 0x68
  92d5d0:	e3002000 	movw	r2, #0
  92d5d4:	ed1f0a4f 	vldr	s0, [pc, #-316]	@ 92d4a0 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x1541c>
  92d5d8:	e59f3850 	ldr	r3, [pc, #2128]	@ 92de30 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15dac>
  92d5dc:	e59dc0bc 	ldr	ip, [sp, #188]	@ 0xbc
  92d5e0:	e793300c 	ldr	r3, [r3, ip]
  92d5e4:	e59fe840 	ldr	lr, [pc, #2112]	@ 92de2c <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15da8>
  92d5e8:	e79ee00c 	ldr	lr, [lr, ip]
  92d5ec:	e59f4818 	ldr	r4, [pc, #2072]	@ 92de0c <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d88>
  92d5f0:	e794400c 	ldr	r4, [r4, ip]
  92d5f4:	e59f5814 	ldr	r5, [pc, #2068]	@ 92de10 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d8c>
  92d5f8:	e795500c 	ldr	r5, [r5, ip]
  92d5fc:	ed9d1a1d 	vldr	s2, [sp, #116]	@ 0x74
  92d600:	ed801a01 	vstr	s2, [r0, #4]
  92d604:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d608:	e5955000 	ldr	r5, [r5]
  92d60c:	e0800005 	add	r0, r0, r5
  92d610:	ed902b00 	vldr	d2, [r0]
  92d614:	eeb73bc2 	vcvt.f32.f64	s6, d2
  92d618:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d61c:	e5944000 	ldr	r4, [r4]
  92d620:	e0800004 	add	r0, r0, r4
  92d624:	ed803a00 	vstr	s6, [r0]
  92d628:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d62c:	e59ee000 	ldr	lr, [lr]
  92d630:	e080000e 	add	r0, r0, lr
  92d634:	ed800a00 	vstr	s0, [r0]
  92d638:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d63c:	e5933000 	ldr	r3, [r3]
  92d640:	e0800003 	add	r0, r0, r3
  92d644:	e58d0070 	str	r0, [sp, #112]	@ 0x70
  92d648:	e1a00001 	mov	r0, r1
  92d64c:	ee101a10 	vmov	r1, s0
  92d650:	ee103a10 	vmov	r3, s0
  92d654:	e58d206c 	str	r2, [sp, #108]	@ 0x6c
  92d658:	e1a02003 	mov	r2, r3
  92d65c:	ebee8b87 	bl	4d0480 <_ZN7Vector2C2Eff>
  92d660:	e59f17a8 	ldr	r1, [pc, #1960]	@ 92de10 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d8c>
  92d664:	e59d20bc 	ldr	r2, [sp, #188]	@ 0xbc
  92d668:	e7911002 	ldr	r1, [r1, r2]
  92d66c:	e30a3000 	movw	r3, #40960	@ 0xa000
  92d670:	ed9f0ac8 	vldr	s0, [pc, #800]	@ 92d998 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15914>
  92d674:	e59fc79c 	ldr	ip, [pc, #1948]	@ 92de18 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d94>
  92d678:	e79cc002 	ldr	ip, [ip, r2]
  92d67c:	e59fe788 	ldr	lr, [pc, #1928]	@ 92de0c <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d88>
  92d680:	e79ee002 	ldr	lr, [lr, r2]
  92d684:	e59f4778 	ldr	r4, [pc, #1912]	@ 92de04 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d80>
  92d688:	e7944002 	ldr	r4, [r4, r2]
  92d68c:	e51b5068 	ldr	r5, [fp, #-104]	@ 0xffffff98
  92d690:	e59d6070 	ldr	r6, [sp, #112]	@ 0x70
  92d694:	e5865000 	str	r5, [r6]
  92d698:	e51b5064 	ldr	r5, [fp, #-100]	@ 0xffffff9c
  92d69c:	e5865004 	str	r5, [r6, #4]
  92d6a0:	ed1b1a11 	vldr	s2, [fp, #-68]	@ 0xffffffbc
  92d6a4:	e51b503c 	ldr	r5, [fp, #-60]	@ 0xffffffc4
  92d6a8:	e5944000 	ldr	r4, [r4]
  92d6ac:	e0854004 	add	r4, r5, r4
  92d6b0:	ed841a00 	vstr	s2, [r4]
  92d6b4:	e51b403c 	ldr	r4, [fp, #-60]	@ 0xffffffc4
  92d6b8:	e59ee000 	ldr	lr, [lr]
  92d6bc:	e084e00e 	add	lr, r4, lr
  92d6c0:	ed9e1a00 	vldr	s2, [lr]
  92d6c4:	ed1b3a11 	vldr	s6, [fp, #-68]	@ 0xffffffbc
  92d6c8:	ee811a03 	vdiv.f32	s2, s2, s6
  92d6cc:	eeb72ac1 	vcvt.f64.f32	d2, s2
  92d6d0:	e51be03c 	ldr	lr, [fp, #-60]	@ 0xffffffc4
  92d6d4:	e5914000 	ldr	r4, [r1]
  92d6d8:	e08ee004 	add	lr, lr, r4
  92d6dc:	ed8e2b00 	vstr	d2, [lr]
  92d6e0:	e51be03c 	ldr	lr, [fp, #-60]	@ 0xffffffc4
  92d6e4:	e59cc000 	ldr	ip, [ip]
  92d6e8:	e08ec00c 	add	ip, lr, ip
  92d6ec:	ed9c1a01 	vldr	s2, [ip, #4]
  92d6f0:	ee800a01 	vdiv.f32	s0, s0, s2
  92d6f4:	ed0b0a1b 	vstr	s0, [fp, #-108]	@ 0xffffff94
  92d6f8:	e51bc03c 	ldr	ip, [fp, #-60]	@ 0xffffffc4
  92d6fc:	e5911000 	ldr	r1, [r1]
  92d700:	e08c1001 	add	r1, ip, r1
  92d704:	ed912b00 	vldr	d2, [r1]
  92d708:	ed1b0a1b 	vldr	s0, [fp, #-108]	@ 0xffffff94
  92d70c:	eeb74ac0 	vcvt.f64.f32	d4, s0
  92d710:	eeb42bc4 	vcmpe.f64	d2, d4
  92d714:	eef1fa10 	vmrs	APSR_nzcv, fpscr
  92d718:	e58d0068 	str	r0, [sp, #104]	@ 0x68
  92d71c:	e58d3064 	str	r3, [sp, #100]	@ 0x64
  92d720:	da000008 	ble	92d748 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x156c4>
  92d724:	e59f06e4 	ldr	r0, [pc, #1764]	@ 92de10 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d8c>
  92d728:	e59d10bc 	ldr	r1, [sp, #188]	@ 0xbc
  92d72c:	e7900001 	ldr	r0, [r0, r1]
  92d730:	ed1b0a1b 	vldr	s0, [fp, #-108]	@ 0xffffff94
  92d734:	eeb71ac0 	vcvt.f64.f32	d1, s0
  92d738:	e51b203c 	ldr	r2, [fp, #-60]	@ 0xffffffc4
  92d73c:	e5900000 	ldr	r0, [r0]
  92d740:	e0820000 	add	r0, r2, r0
  92d744:	ed801b00 	vstr	d1, [r0]
  92d748:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d74c:	e59f16e4 	ldr	r1, [pc, #1764]	@ 92de38 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15db4>
  92d750:	e59f26fc 	ldr	r2, [pc, #1788]	@ 92de54 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15dd0>
  92d754:	e08f2002 	add	r2, pc, r2
  92d758:	e7911002 	ldr	r1, [r1, r2]
  92d75c:	e5911000 	ldr	r1, [r1]
  92d760:	e0803001 	add	r3, r0, r1
  92d764:	e59fc6a4 	ldr	ip, [pc, #1700]	@ 92de10 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d8c>
  92d768:	e79cc002 	ldr	ip, [ip, r2]
  92d76c:	e59ce000 	ldr	lr, [ip]
  92d770:	e080e00e 	add	lr, r0, lr
  92d774:	ed9e0b00 	vldr	d0, [lr]
  92d778:	eeb71bc0 	vcvt.f32.f64	s2, d0
  92d77c:	ee11ea10 	vmov	lr, s2
  92d780:	e24b4078 	sub	r4, fp, #120	@ 0x78
  92d784:	e58d0060 	str	r0, [sp, #96]	@ 0x60
  92d788:	e1a00004 	mov	r0, r4
  92d78c:	e58d105c 	str	r1, [sp, #92]	@ 0x5c
  92d790:	e1a01003 	mov	r1, r3
  92d794:	e58d2058 	str	r2, [sp, #88]	@ 0x58
  92d798:	e1a0200e 	mov	r2, lr
  92d79c:	e58d3054 	str	r3, [sp, #84]	@ 0x54
  92d7a0:	e58dc050 	str	ip, [sp, #80]	@ 0x50
  92d7a4:	ebee8aef 	bl	4d0368 <_ZN7Vector2mlEf>
  92d7a8:	e51b0078 	ldr	r0, [fp, #-120]	@ 0xffffff88
  92d7ac:	e51b1074 	ldr	r1, [fp, #-116]	@ 0xffffff8c
  92d7b0:	e59d2060 	ldr	r2, [sp, #96]	@ 0x60
  92d7b4:	e59d305c 	ldr	r3, [sp, #92]	@ 0x5c
  92d7b8:	e7820003 	str	r0, [r2, r3]
  92d7bc:	e59d0054 	ldr	r0, [sp, #84]	@ 0x54
  92d7c0:	e5801004 	str	r1, [r0, #4]
  92d7c4:	e51b103c 	ldr	r1, [fp, #-60]	@ 0xffffffc4
  92d7c8:	e59dc050 	ldr	ip, [sp, #80]	@ 0x50
  92d7cc:	e59ce000 	ldr	lr, [ip]
  92d7d0:	e081100e 	add	r1, r1, lr
  92d7d4:	ed910b00 	vldr	d0, [r1]
  92d7d8:	ed0b0b20 	vstr	d0, [fp, #-128]	@ 0xffffff80
  92d7dc:	e51b103c 	ldr	r1, [fp, #-60]	@ 0xffffffc4
  92d7e0:	e59fe5fc 	ldr	lr, [pc, #1532]	@ 92dde4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d60>
  92d7e4:	e59d4058 	ldr	r4, [sp, #88]	@ 0x58
  92d7e8:	e79ee004 	ldr	lr, [lr, r4]
  92d7ec:	e59ee000 	ldr	lr, [lr]
  92d7f0:	e791000e 	ldr	r0, [r1, lr]
  92d7f4:	e59f1618 	ldr	r1, [pc, #1560]	@ 92de14 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d90>
  92d7f8:	e7911004 	ldr	r1, [r1, r4]
  92d7fc:	ebe25406 	bl	1c281c <objc_msgSend@plt>
  92d800:	eeb41a00 	vmov.f32	s2, #64	@ 0x3e000000  0.125
  92d804:	eeb62a00 	vmov.f32	s4, #96	@ 0x3f000000  0.5
  92d808:	e31000ff 	tst	r0, #255	@ 0xff
  92d80c:	1eb02a41 	vmovne.f32	s4, s2
  92d810:	ed0b2a21 	vstr	s4, [fp, #-132]	@ 0xffffff7c
  92d814:	ed1b0b20 	vldr	d0, [fp, #-128]	@ 0xffffff80
  92d818:	ed1b1a21 	vldr	s2, [fp, #-132]	@ 0xffffff7c
  92d81c:	eeb73ac1 	vcvt.f64.f32	d3, s2
  92d820:	eeb40bc3 	vcmpe.f64	d0, d3
  92d824:	eef1fa10 	vmrs	APSR_nzcv, fpscr
  92d828:	5a000003 	bpl	92d83c <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x157b8>
  92d82c:	ed1b0a21 	vldr	s0, [fp, #-132]	@ 0xffffff7c
  92d830:	eeb71ac0 	vcvt.f64.f32	d1, s0
  92d834:	ed8d1b12 	vstr	d1, [sp, #72]	@ 0x48
  92d838:	ea000001 	b	92d844 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x157c0>
  92d83c:	ed1b0b20 	vldr	d0, [fp, #-128]	@ 0xffffff80
  92d840:	ed8d0b12 	vstr	d0, [sp, #72]	@ 0x48
  92d844:	ed9d0b12 	vldr	d0, [sp, #72]	@ 0x48
  92d848:	e3000001 	movw	r0, #1
  92d84c:	e59f15ac 	ldr	r1, [pc, #1452]	@ 92de00 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d7c>
  92d850:	e59d20bc 	ldr	r2, [sp, #188]	@ 0xbc
  92d854:	e7911002 	ldr	r1, [r1, r2]
  92d858:	e59f357c 	ldr	r3, [pc, #1404]	@ 92dddc <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d58>
  92d85c:	e7933002 	ldr	r3, [r3, r2]
  92d860:	e59fc5b4 	ldr	ip, [pc, #1460]	@ 92de1c <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d98>
  92d864:	e08cc002 	add	ip, ip, r2
  92d868:	e59fe5a0 	ldr	lr, [pc, #1440]	@ 92de10 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d8c>
  92d86c:	e79ee002 	ldr	lr, [lr, r2]
  92d870:	ed0b0b24 	vstr	d0, [fp, #-144]	@ 0xffffff70
  92d874:	ed1b0b24 	vldr	d0, [fp, #-144]	@ 0xffffff70
  92d878:	e51b403c 	ldr	r4, [fp, #-60]	@ 0xffffffc4
  92d87c:	e59ee000 	ldr	lr, [lr]
  92d880:	e084e00e 	add	lr, r4, lr
  92d884:	ed8e0b00 	vstr	d0, [lr]
  92d888:	e51be03c 	ldr	lr, [fp, #-60]	@ 0xffffffc4
  92d88c:	e59cc000 	ldr	ip, [ip]
  92d890:	e58d0044 	str	r0, [sp, #68]	@ 0x44
  92d894:	e1a0000e 	mov	r0, lr
  92d898:	e58d1040 	str	r1, [sp, #64]	@ 0x40
  92d89c:	e1a0100c 	mov	r1, ip
  92d8a0:	e12fff33 	blx	r3
  92d8a4:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d8a8:	e59d1040 	ldr	r1, [sp, #64]	@ 0x40
  92d8ac:	e5912000 	ldr	r2, [r1]
  92d8b0:	e0800002 	add	r0, r0, r2
  92d8b4:	e59d2044 	ldr	r2, [sp, #68]	@ 0x44
  92d8b8:	e5c02000 	strb	r2, [r0]
  92d8bc:	ea000143 	b	92ddd0 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d4c>
  92d8c0:	e51b004c 	ldr	r0, [fp, #-76]	@ 0xffffffb4
  92d8c4:	e3500002 	cmp	r0, #2
  92d8c8:	1a000130 	bne	92dd90 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d0c>
  92d8cc:	ed1b0a11 	vldr	s0, [fp, #-68]	@ 0xffffffbc
  92d8d0:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d8d4:	e59f1528 	ldr	r1, [pc, #1320]	@ 92de04 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d80>
  92d8d8:	e59f2528 	ldr	r2, [pc, #1320]	@ 92de08 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d84>
  92d8dc:	e08f2002 	add	r2, pc, r2
  92d8e0:	e7911002 	ldr	r1, [r1, r2]
  92d8e4:	e5911000 	ldr	r1, [r1]
  92d8e8:	e0800001 	add	r0, r0, r1
  92d8ec:	ed800a00 	vstr	s0, [r0]
  92d8f0:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d8f4:	e59f1510 	ldr	r1, [pc, #1296]	@ 92de0c <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d88>
  92d8f8:	e7911002 	ldr	r1, [r1, r2]
  92d8fc:	e5911000 	ldr	r1, [r1]
  92d900:	e0801001 	add	r1, r0, r1
  92d904:	ed910a00 	vldr	s0, [r1]
  92d908:	ed1b1a11 	vldr	s2, [fp, #-68]	@ 0xffffffbc
  92d90c:	ee800a01 	vdiv.f32	s0, s0, s2
  92d910:	eeb72ac0 	vcvt.f64.f32	d2, s0
  92d914:	e59f14f4 	ldr	r1, [pc, #1268]	@ 92de10 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d8c>
  92d918:	e7911002 	ldr	r1, [r1, r2]
  92d91c:	e5913000 	ldr	r3, [r1]
  92d920:	e0800003 	add	r0, r0, r3
  92d924:	ed802b00 	vstr	d2, [r0]
  92d928:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d92c:	e5911000 	ldr	r1, [r1]
  92d930:	e0800001 	add	r0, r0, r1
  92d934:	ed902b00 	vldr	d2, [r0]
  92d938:	ed0b2b26 	vstr	d2, [fp, #-152]	@ 0xffffff68
  92d93c:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92d940:	e59f149c 	ldr	r1, [pc, #1180]	@ 92dde4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d60>
  92d944:	e7911002 	ldr	r1, [r1, r2]
  92d948:	e5911000 	ldr	r1, [r1]
  92d94c:	e7900001 	ldr	r0, [r0, r1]
  92d950:	e59f14bc 	ldr	r1, [pc, #1212]	@ 92de14 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d90>
  92d954:	e7911002 	ldr	r1, [r1, r2]
  92d958:	ebe253af 	bl	1c281c <objc_msgSend@plt>
  92d95c:	eeb40a00 	vmov.f32	s0, #64	@ 0x3e000000  0.125
  92d960:	eeb61a00 	vmov.f32	s2, #96	@ 0x3f000000  0.5
  92d964:	e31000ff 	tst	r0, #255	@ 0xff
  92d968:	1eb01a40 	vmovne.f32	s2, s0
  92d96c:	ed0b1a27 	vstr	s2, [fp, #-156]	@ 0xffffff64
  92d970:	ed1b2b26 	vldr	d2, [fp, #-152]	@ 0xffffff68
  92d974:	ed1b0a27 	vldr	s0, [fp, #-156]	@ 0xffffff64
  92d978:	eeb73ac0 	vcvt.f64.f32	d3, s0
  92d97c:	eeb42bc3 	vcmpe.f64	d2, d3
  92d980:	eef1fa10 	vmrs	APSR_nzcv, fpscr
  92d984:	5a000004 	bpl	92d99c <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15918>
  92d988:	ed1b0a27 	vldr	s0, [fp, #-156]	@ 0xffffff64
  92d98c:	eeb71ac0 	vcvt.f64.f32	d1, s0
  92d990:	ed8d1b0e 	vstr	d1, [sp, #56]	@ 0x38
  92d994:	ea000002 	b	92d9a4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15920>
  92d998:	47200000 	strmi	r0, [r0, -r0]!
  92d99c:	ed1b0b26 	vldr	d0, [fp, #-152]	@ 0xffffff68
  92d9a0:	ed8d0b0e 	vstr	d0, [sp, #56]	@ 0x38
  92d9a4:	ed9d0b0e 	vldr	d0, [sp, #56]	@ 0x38
  92d9a8:	e59f0460 	ldr	r0, [pc, #1120]	@ 92de10 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d8c>
  92d9ac:	e59d10bc 	ldr	r1, [sp, #188]	@ 0xbc
  92d9b0:	e7900001 	ldr	r0, [r0, r1]
  92d9b4:	e30a2000 	movw	r2, #40960	@ 0xa000
  92d9b8:	ed1f1a0a 	vldr	s2, [pc, #-40]	@ 92d998 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15914>
  92d9bc:	e59f3454 	ldr	r3, [pc, #1108]	@ 92de18 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d94>
  92d9c0:	e7933001 	ldr	r3, [r3, r1]
  92d9c4:	e59fc410 	ldr	ip, [pc, #1040]	@ 92dddc <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d58>
  92d9c8:	e79cc001 	ldr	ip, [ip, r1]
  92d9cc:	e59fe448 	ldr	lr, [pc, #1096]	@ 92de1c <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d98>
  92d9d0:	e08ee001 	add	lr, lr, r1
  92d9d4:	ed0b0b2a 	vstr	d0, [fp, #-168]	@ 0xffffff58
  92d9d8:	ed1b0b2a 	vldr	d0, [fp, #-168]	@ 0xffffff58
  92d9dc:	e51b403c 	ldr	r4, [fp, #-60]	@ 0xffffffc4
  92d9e0:	e5905000 	ldr	r5, [r0]
  92d9e4:	e0844005 	add	r4, r4, r5
  92d9e8:	ed840b00 	vstr	d0, [r4]
  92d9ec:	e51b403c 	ldr	r4, [fp, #-60]	@ 0xffffffc4
  92d9f0:	e59e1000 	ldr	r1, [lr]
  92d9f4:	e58d0034 	str	r0, [sp, #52]	@ 0x34
  92d9f8:	e1a00004 	mov	r0, r4
  92d9fc:	e58d2030 	str	r2, [sp, #48]	@ 0x30
  92da00:	ed8d1a0b 	vstr	s2, [sp, #44]	@ 0x2c
  92da04:	e58d3028 	str	r3, [sp, #40]	@ 0x28
  92da08:	e12fff3c 	blx	ip
  92da0c:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92da10:	e59d1028 	ldr	r1, [sp, #40]	@ 0x28
  92da14:	e5912000 	ldr	r2, [r1]
  92da18:	e0800002 	add	r0, r0, r2
  92da1c:	ed901a01 	vldr	s2, [r0, #4]
  92da20:	ed9d2a0b 	vldr	s4, [sp, #44]	@ 0x2c
  92da24:	ee821a01 	vdiv.f32	s2, s4, s2
  92da28:	ed0b1a2b 	vstr	s2, [fp, #-172]	@ 0xffffff54
  92da2c:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92da30:	e59d2034 	ldr	r2, [sp, #52]	@ 0x34
  92da34:	e5923000 	ldr	r3, [r2]
  92da38:	e0800003 	add	r0, r0, r3
  92da3c:	ed900b00 	vldr	d0, [r0]
  92da40:	ed1b1a2b 	vldr	s2, [fp, #-172]	@ 0xffffff54
  92da44:	eeb73ac1 	vcvt.f64.f32	d3, s2
  92da48:	eeb40bc3 	vcmpe.f64	d0, d3
  92da4c:	eef1fa10 	vmrs	APSR_nzcv, fpscr
  92da50:	ca00002a 	bgt	92db00 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15a7c>
  92da54:	eeb60b00 	vmov.f64	d0, #96	@ 0x3f000000  0.5
  92da58:	e59f03b0 	ldr	r0, [pc, #944]	@ 92de10 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d8c>
  92da5c:	e59d10bc 	ldr	r1, [sp, #188]	@ 0xbc
  92da60:	e7900001 	ldr	r0, [r0, r1]
  92da64:	e51b203c 	ldr	r2, [fp, #-60]	@ 0xffffffc4
  92da68:	e5900000 	ldr	r0, [r0]
  92da6c:	e0820000 	add	r0, r2, r0
  92da70:	ed901b00 	vldr	d1, [r0]
  92da74:	eeb41bc0 	vcmpe.f64	d1, d0
  92da78:	eef1fa10 	vmrs	APSR_nzcv, fpscr
  92da7c:	4a00001f 	bmi	92db00 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15a7c>
  92da80:	ed1b0a12 	vldr	s0, [fp, #-72]	@ 0xffffffb8
  92da84:	ed0b0a0b 	vstr	s0, [fp, #-44]	@ 0xffffffd4
  92da88:	ed1b0a0b 	vldr	s0, [fp, #-44]	@ 0xffffffd4
  92da8c:	ed0b0a0a 	vstr	s0, [fp, #-40]	@ 0xffffffd8
  92da90:	ed1b0a0a 	vldr	s0, [fp, #-40]	@ 0xffffffd8
  92da94:	ee100a10 	vmov	r0, s0
  92da98:	ebe259dd 	bl	1c4214 <isnanf@plt>
  92da9c:	e3500000 	cmp	r0, #0
  92daa0:	1a000016 	bne	92db00 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15a7c>
  92daa4:	e3e00063 	mvn	r0, #99	@ 0x63
  92daa8:	ed9f0adc 	vldr	s0, [pc, #880]	@ 92de20 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d9c>
  92daac:	ed1b1a12 	vldr	s2, [fp, #-72]	@ 0xffffffb8
  92dab0:	eeb41ac0 	vcmpe.f32	s2, s0
  92dab4:	eef1fa10 	vmrs	APSR_nzcv, fpscr
  92dab8:	e58d0024 	str	r0, [sp, #36]	@ 0x24
  92dabc:	da00000f 	ble	92db00 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15a7c>
  92dac0:	e3000064 	movw	r0, #100	@ 0x64
  92dac4:	ed9f0ad6 	vldr	s0, [pc, #856]	@ 92de24 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15da0>
  92dac8:	ed1b1a12 	vldr	s2, [fp, #-72]	@ 0xffffffb8
  92dacc:	eeb41ac0 	vcmpe.f32	s2, s0
  92dad0:	eef1fa10 	vmrs	APSR_nzcv, fpscr
  92dad4:	e58d0020 	str	r0, [sp, #32]
  92dad8:	5a000008 	bpl	92db00 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15a7c>
  92dadc:	ed1b0a12 	vldr	s0, [fp, #-72]	@ 0xffffffb8
  92dae0:	ed0b0a09 	vstr	s0, [fp, #-36]	@ 0xffffffdc
  92dae4:	ed1b0a09 	vldr	s0, [fp, #-36]	@ 0xffffffdc
  92dae8:	ed0b0a08 	vstr	s0, [fp, #-32]	@ 0xffffffe0
  92daec:	ed1b0a08 	vldr	s0, [fp, #-32]	@ 0xffffffe0
  92daf0:	ee100a10 	vmov	r0, s0
  92daf4:	ebe259c9 	bl	1c4220 <__isfinitef@plt>
  92daf8:	e3500000 	cmp	r0, #0
  92dafc:	1a000000 	bne	92db04 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15a80>
  92db00:	ea00000e 	b	92db40 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15abc>
  92db04:	e3000001 	movw	r0, #1
  92db08:	e59f1318 	ldr	r1, [pc, #792]	@ 92de28 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15da4>
  92db0c:	e59d20bc 	ldr	r2, [sp, #188]	@ 0xbc
  92db10:	e7911002 	ldr	r1, [r1, r2]
  92db14:	e59f3310 	ldr	r3, [pc, #784]	@ 92de2c <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15da8>
  92db18:	e7933002 	ldr	r3, [r3, r2]
  92db1c:	ed1b0a12 	vldr	s0, [fp, #-72]	@ 0xffffffb8
  92db20:	e51bc03c 	ldr	ip, [fp, #-60]	@ 0xffffffc4
  92db24:	e5933000 	ldr	r3, [r3]
  92db28:	e08c3003 	add	r3, ip, r3
  92db2c:	ed830a00 	vstr	s0, [r3]
  92db30:	e51b303c 	ldr	r3, [fp, #-60]	@ 0xffffffc4
  92db34:	e5911000 	ldr	r1, [r1]
  92db38:	e0831001 	add	r1, r3, r1
  92db3c:	e5c10000 	strb	r0, [r1]
  92db40:	e59f02c8 	ldr	r0, [pc, #712]	@ 92de10 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d8c>
  92db44:	e59d10bc 	ldr	r1, [sp, #188]	@ 0xbc
  92db48:	e7900001 	ldr	r0, [r0, r1]
  92db4c:	e51b203c 	ldr	r2, [fp, #-60]	@ 0xffffffc4
  92db50:	e5900000 	ldr	r0, [r0]
  92db54:	e0820000 	add	r0, r2, r0
  92db58:	ed900b00 	vldr	d0, [r0]
  92db5c:	ed1b1a2b 	vldr	s2, [fp, #-172]	@ 0xffffff54
  92db60:	eeb72ac1 	vcvt.f64.f32	d2, s2
  92db64:	eeb40bc2 	vcmpe.f64	d0, d2
  92db68:	eef1fa10 	vmrs	APSR_nzcv, fpscr
  92db6c:	da000009 	ble	92db98 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15b14>
  92db70:	e59f0298 	ldr	r0, [pc, #664]	@ 92de10 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d8c>
  92db74:	e59d10bc 	ldr	r1, [sp, #188]	@ 0xbc
  92db78:	e7900001 	ldr	r0, [r0, r1]
  92db7c:	ed1b0a2b 	vldr	s0, [fp, #-172]	@ 0xffffff54
  92db80:	eeb71ac0 	vcvt.f64.f32	d1, s0
  92db84:	e51b203c 	ldr	r2, [fp, #-60]	@ 0xffffffc4
  92db88:	e5900000 	ldr	r0, [r0]
  92db8c:	e0820000 	add	r0, r2, r0
  92db90:	ed801b00 	vstr	d1, [r0]
  92db94:	ea00004b 	b	92dcc8 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15c44>
  92db98:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92db9c:	e59f128c 	ldr	r1, [pc, #652]	@ 92de30 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15dac>
  92dba0:	e59f228c 	ldr	r2, [pc, #652]	@ 92de34 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15db0>
  92dba4:	e08f2002 	add	r2, pc, r2
  92dba8:	e7911002 	ldr	r1, [r1, r2]
  92dbac:	e5913000 	ldr	r3, [r1]
  92dbb0:	e080c003 	add	ip, r0, r3
  92dbb4:	e59fe27c 	ldr	lr, [pc, #636]	@ 92de38 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15db4>
  92dbb8:	e79e2002 	ldr	r2, [lr, r2]
  92dbbc:	e592e000 	ldr	lr, [r2]
  92dbc0:	e080e00e 	add	lr, r0, lr
  92dbc4:	e51b4044 	ldr	r4, [fp, #-68]	@ 0xffffffbc
  92dbc8:	e24b50c0 	sub	r5, fp, #192	@ 0xc0
  92dbcc:	e58d001c 	str	r0, [sp, #28]
  92dbd0:	e1a00005 	mov	r0, r5
  92dbd4:	e58d1018 	str	r1, [sp, #24]
  92dbd8:	e1a0100e 	mov	r1, lr
  92dbdc:	e58d2014 	str	r2, [sp, #20]
  92dbe0:	e1a02004 	mov	r2, r4
  92dbe4:	e58d5010 	str	r5, [sp, #16]
  92dbe8:	e58dc00c 	str	ip, [sp, #12]
  92dbec:	e58d3008 	str	r3, [sp, #8]
  92dbf0:	ebee89f2 	bl	4d03c0 <_ZN7Vector2dvEf>
  92dbf4:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92dbf8:	e59d1014 	ldr	r1, [sp, #20]
  92dbfc:	e5912000 	ldr	r2, [r1]
  92dc00:	e7b02002 	ldr	r2, [r0, r2]!
  92dc04:	e50b20c8 	str	r2, [fp, #-200]	@ 0xffffff38
  92dc08:	e5900004 	ldr	r0, [r0, #4]
  92dc0c:	e50b00c4 	str	r0, [fp, #-196]	@ 0xffffff3c
  92dc10:	e51b20c8 	ldr	r2, [fp, #-200]	@ 0xffffff38
  92dc14:	e51b30c4 	ldr	r3, [fp, #-196]	@ 0xffffff3c
  92dc18:	e24b00d0 	sub	r0, fp, #208	@ 0xd0
  92dc1c:	e58d0004 	str	r0, [sp, #4]
  92dc20:	e59d1010 	ldr	r1, [sp, #16]
  92dc24:	ebee8a22 	bl	4d04b4 <_ZN7Vector2miES_>
  92dc28:	e24b00b8 	sub	r0, fp, #184	@ 0xb8
  92dc2c:	e30c2ccd 	movw	r2, #52429	@ 0xcccd
  92dc30:	e3432ccc 	movt	r2, #15564	@ 0x3ccc
  92dc34:	e59d1004 	ldr	r1, [sp, #4]
  92dc38:	ebee89ca 	bl	4d0368 <_ZN7Vector2mlEf>
  92dc3c:	e51b00b8 	ldr	r0, [fp, #-184]	@ 0xffffff48
  92dc40:	e51b10b4 	ldr	r1, [fp, #-180]	@ 0xffffff4c
  92dc44:	e59d201c 	ldr	r2, [sp, #28]
  92dc48:	e59d3008 	ldr	r3, [sp, #8]
  92dc4c:	e7820003 	str	r0, [r2, r3]
  92dc50:	e59d000c 	ldr	r0, [sp, #12]
  92dc54:	e5801004 	str	r1, [r0, #4]
  92dc58:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92dc5c:	e59d1018 	ldr	r1, [sp, #24]
  92dc60:	e591c000 	ldr	ip, [r1]
  92dc64:	e080000c 	add	r0, r0, ip
  92dc68:	e24bc0e0 	sub	ip, fp, #224	@ 0xe0
  92dc6c:	e3a0e000 	mov	lr, #0
  92dc70:	e58d0000 	str	r0, [sp]
  92dc74:	e1a0000c 	mov	r0, ip
  92dc78:	e1a0100e 	mov	r1, lr
  92dc7c:	e1a0200e 	mov	r2, lr
  92dc80:	ebee89fe 	bl	4d0480 <_ZN7Vector2C2Eff>
  92dc84:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92dc88:	e59d1018 	ldr	r1, [sp, #24]
  92dc8c:	e5912000 	ldr	r2, [r1]
  92dc90:	e7b02002 	ldr	r2, [r0, r2]!
  92dc94:	e58d20e0 	str	r2, [sp, #224]	@ 0xe0
  92dc98:	e5900004 	ldr	r0, [r0, #4]
  92dc9c:	e58d00e4 	str	r0, [sp, #228]	@ 0xe4
  92dca0:	e59d20e0 	ldr	r2, [sp, #224]	@ 0xe0
  92dca4:	e59d30e4 	ldr	r3, [sp, #228]	@ 0xe4
  92dca8:	e24b00d8 	sub	r0, fp, #216	@ 0xd8
  92dcac:	e24b10e0 	sub	r1, fp, #224	@ 0xe0
  92dcb0:	ebee89ff 	bl	4d04b4 <_ZN7Vector2miES_>
  92dcb4:	e51b00d8 	ldr	r0, [fp, #-216]	@ 0xffffff28
  92dcb8:	e59d1000 	ldr	r1, [sp]
  92dcbc:	e5810000 	str	r0, [r1]
  92dcc0:	e51b00d4 	ldr	r0, [fp, #-212]	@ 0xffffff2c
  92dcc4:	e5810004 	str	r0, [r1, #4]
  92dcc8:	e59f016c 	ldr	r0, [pc, #364]	@ 92de3c <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15db8>
  92dccc:	e59d10bc 	ldr	r1, [sp, #188]	@ 0xbc
  92dcd0:	e7900001 	ldr	r0, [r0, r1]
  92dcd4:	e59f2154 	ldr	r2, [pc, #340]	@ 92de30 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15dac>
  92dcd8:	e7922001 	ldr	r2, [r2, r1]
  92dcdc:	e51b303c 	ldr	r3, [fp, #-60]	@ 0xffffffc4
  92dce0:	e5922000 	ldr	r2, [r2]
  92dce4:	e0832002 	add	r2, r3, r2
  92dce8:	e5923000 	ldr	r3, [r2]
  92dcec:	e58d30d8 	str	r3, [sp, #216]	@ 0xd8
  92dcf0:	e5922004 	ldr	r2, [r2, #4]
  92dcf4:	e58d20dc 	str	r2, [sp, #220]	@ 0xdc
  92dcf8:	e51b203c 	ldr	r2, [fp, #-60]	@ 0xffffffc4
  92dcfc:	e5900000 	ldr	r0, [r0]
  92dd00:	e0820000 	add	r0, r2, r0
  92dd04:	e1d000d0 	ldrsb	r0, [r0]
  92dd08:	e3500000 	cmp	r0, #0
  92dd0c:	0a000012 	beq	92dd5c <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15cd8>
  92dd10:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92dd14:	e59f1124 	ldr	r1, [pc, #292]	@ 92de40 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15dbc>
  92dd18:	e59f2124 	ldr	r2, [pc, #292]	@ 92de44 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15dc0>
  92dd1c:	e08f2002 	add	r2, pc, r2
  92dd20:	e7911002 	ldr	r1, [r1, r2]
  92dd24:	e5911000 	ldr	r1, [r1]
  92dd28:	e7b01001 	ldr	r1, [r0, r1]!
  92dd2c:	e58d10c8 	str	r1, [sp, #200]	@ 0xc8
  92dd30:	e5900004 	ldr	r0, [r0, #4]
  92dd34:	e58d00cc 	str	r0, [sp, #204]	@ 0xcc
  92dd38:	e59d20c8 	ldr	r2, [sp, #200]	@ 0xc8
  92dd3c:	e59d30cc 	ldr	r3, [sp, #204]	@ 0xcc
  92dd40:	e28d00d0 	add	r0, sp, #208	@ 0xd0
  92dd44:	e28d10d8 	add	r1, sp, #216	@ 0xd8
  92dd48:	ebee89b2 	bl	4d0418 <_ZN7Vector2plES_>
  92dd4c:	e59d00d0 	ldr	r0, [sp, #208]	@ 0xd0
  92dd50:	e58d00d8 	str	r0, [sp, #216]	@ 0xd8
  92dd54:	e59d00d4 	ldr	r0, [sp, #212]	@ 0xd4
  92dd58:	e58d00dc 	str	r0, [sp, #220]	@ 0xdc
  92dd5c:	e51b003c 	ldr	r0, [fp, #-60]	@ 0xffffffc4
  92dd60:	e59d10d8 	ldr	r1, [sp, #216]	@ 0xd8
  92dd64:	e59d20dc 	ldr	r2, [sp, #220]	@ 0xdc
  92dd68:	e58d20c4 	str	r2, [sp, #196]	@ 0xc4
  92dd6c:	e58d10c0 	str	r1, [sp, #192]	@ 0xc0
  92dd70:	e59f10d0 	ldr	r1, [pc, #208]	@ 92de48 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15dc4>
  92dd74:	e59f20d0 	ldr	r2, [pc, #208]	@ 92de4c <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15dc8>
  92dd78:	e08f2002 	add	r2, pc, r2
  92dd7c:	e7911002 	ldr	r1, [r1, r2]
  92dd80:	e59d20c0 	ldr	r2, [sp, #192]	@ 0xc0
  92dd84:	e59d30c4 	ldr	r3, [sp, #196]	@ 0xc4
  92dd88:	ebe252a3 	bl	1c281c <objc_msgSend@plt>
  92dd8c:	ea00000e 	b	92ddcc <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d48>
  92dd90:	e51b004c 	ldr	r0, [fp, #-76]	@ 0xffffffb4
  92dd94:	e3500003 	cmp	r0, #3
  92dd98:	0a000002 	beq	92dda8 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d24>
  92dd9c:	e51b004c 	ldr	r0, [fp, #-76]	@ 0xffffffb4
  92dda0:	e3500004 	cmp	r0, #4
  92dda4:	1a000007 	bne	92ddc8 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d44>
  92dda8:	e3000000 	movw	r0, #0
  92ddac:	e59f104c 	ldr	r1, [pc, #76]	@ 92de00 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d7c>
  92ddb0:	e59d20bc 	ldr	r2, [sp, #188]	@ 0xbc
  92ddb4:	e7911002 	ldr	r1, [r1, r2]
  92ddb8:	e51b303c 	ldr	r3, [fp, #-60]	@ 0xffffffc4
  92ddbc:	e5911000 	ldr	r1, [r1]
  92ddc0:	e0831001 	add	r1, r3, r1
  92ddc4:	e5c10000 	strb	r0, [r1]
  92ddc8:	eaffffff 	b	92ddcc <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d48>
  92ddcc:	eaffffff 	b	92ddd0 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d4c>
  92ddd0:	eaffffff 	b	92ddd4 <_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc+0x15d50>
  92ddd4:	e24bd018 	sub	sp, fp, #24
  92ddd8:	e8bd8df0 	pop	{r4, r5, r6, r7, r8, sl, fp, pc}
  92dddc:	ffffbcac 			@ <UNDEFINED> instruction: 0xffffbcac
  92dde0:	ffe23adc 			@ <UNDEFINED> instruction: 0xffe23adc
  92dde4:	ffffe61c 			@ <UNDEFINED> instruction: 0xffffe61c
  92dde8:	ffffe6b8 			@ <UNDEFINED> instruction: 0xffffe6b8
  92ddec:	ffe23bd0 			@ <UNDEFINED> instruction: 0xffe23bd0
  92ddf0:	ffe23944 			@ <UNDEFINED> instruction: 0xffe23944
  92ddf4:	ffe23ad4 			@ <UNDEFINED> instruction: 0xffe23ad4
  92ddf8:	ffe23bd4 			@ <UNDEFINED> instruction: 0xffe23bd4
  92ddfc:	ffe23bd8 			@ <UNDEFINED> instruction: 0xffe23bd8
  92de00:	ffffe6ac 			@ <UNDEFINED> instruction: 0xffffe6ac
  92de04:	ffffe6c4 			@ <UNDEFINED> instruction: 0xffffe6c4
  92de08:	00732210 	rsbseq	r2, r3, r0, lsl r2
  92de0c:	ffffe6c8 			@ <UNDEFINED> instruction: 0xffffe6c8
  92de10:	ffffe62c 			@ <UNDEFINED> instruction: 0xffffe62c
  92de14:	ffe23af4 			@ <UNDEFINED> instruction: 0xffe23af4
  92de18:	ffffe694 			@ <UNDEFINED> instruction: 0xffffe694
  92de1c:	ffe23af8 			@ <UNDEFINED> instruction: 0xffe23af8
  92de20:	c2c80000 	sbcgt	r0, r8, #0
  92de24:	42c80000 	sbcmi	r0, r8, #0
  92de28:	ffffe6bc 			@ <UNDEFINED> instruction: 0xffffe6bc
  92de2c:	ffffe6c0 			@ <UNDEFINED> instruction: 0xffffe6c0
  92de30:	ffffe734 			@ <UNDEFINED> instruction: 0xffffe734
  92de34:	00731f48 	rsbseq	r1, r3, r8, asr #30
  92de38:	ffffe738 			@ <UNDEFINED> instruction: 0xffffe738
  92de3c:	ffffe6a8 			@ <UNDEFINED> instruction: 0xffffe6a8
  92de40:	ffffe73c 			@ <UNDEFINED> instruction: 0xffffe73c
  92de44:	00731dd0 	ldrsbteq	r1, [r3], #-208	@ 0xffffff30
  92de48:	ffe23be0 			@ <UNDEFINED> instruction: 0xffe23be0
  92de4c:	00731d74 	rsbseq	r1, r3, r4, ror sp
  92de50:	ffe23bdc 			@ <UNDEFINED> instruction: 0xffe23bdc
  92de54:	00732398 			@ <UNDEFINED> instruction: 0x00732398
  92de58:	00732918 	rsbseq	r2, r3, r8, lsl r9
