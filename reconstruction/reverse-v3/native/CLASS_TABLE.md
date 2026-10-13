# Class metadata (machine-extracted from the pinned ELF)

Source: `tools/elf_class_metadata.py` over sha256 `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.
Classes: 536. Ivar layouts below are authoritative (they are what the harnesses have been pinning by hand).

## Classes with ivars (449 of 536)

| class | super | size | ivars (name@offset) |
|---|---|---:|---|
| ASIdentifierManager | - | 12 | _advertisingTrackingEnabled@4, _advertisingIdentifier@8 |
| AVAsset | - | 72 | _url@4, _preferredRate@8, _preferredVolume@12, _naturalSize@16, _duration@24, _preferredTransform@48 |
| AVAssetReader | - | 68 | _asset@4, _status@8, _error@12, _outputs@16, _timeRange@20 |
| AVAudioPlayer | - | 72 | _pan@4, _volume@8, _enableRate@12, _rate@16, _currentTime@24, _numberOfLoops@32, _meteringEnabled@36, _audioId@40, _playing@44, _numberOfChannels@48, _delegate@52, _url@56, … (+3) |
| AVAudioRecorder | - | 32 | _recording@4, _meteringEnabled@5, _url@8, _settings@12, _delegate@16, _currentTime@24 |
| AVAudioSession | - | 88 | mode@4, category@8, delegate@12, currentHardwareInputNumberOfChannels@16, currentHardwareOutputNumberOfChannels@20, inputNumberOfChannels@24, outputNumberOfChannels@28, categoryOptions@32, _currentRoute@36, _inputDataSource@40, preferredHardwareSampleRate@48, preferredIOBufferDuration@56, … (+3) |
| AVPlayer | - | 24 | status@4, error@8, rate@12, currentItem@16, actionAtItemEnd@20 |
| AVPlayerLayer | CALayer | 16 | readyForDisplay@4, player@8, videoGravity@12 |
| AVSynchronizedLayer | CALayer | 8 | _playerItem@4 |
| AVURLAsset | AVAsset | 76 | _url@72 |
| Action | - | 72 | inProgress@4, complete@5, isAI@6, goalTilePos@8, interactionItem@16, interactionItemIndex@20, interactionItemSubIndex@22, goalInteraction@24, pathType@28, interactionObjectID@32, craftableItemObject@40, craftCountOrExtraData@44, … (+4) |
| AddCreditUI | - | 168 | worldName@4, worldID@8, delegate@12, skRequest@16, creditProducts@20, backgroundShader@28, backgroundTexture@32, titleTextView@36, blackBackgroundShader@40, orthoMatrix@48, windowInfo@112, cache@116, … (+11) |
| AddFuelUI | GameUIView | 156 | world@20, backgroundShader@24, backgroundTexture@28, fuelIndicatorOn@32, fuelIndicatorOff@36, fuelButtons@40, fuelInventoryCounts@44, fuelBlockCubes@48, orthoMatrix@64, windowInfo@128, cache@132, fuelObject@136, … (+3) |
| AndroidUbiquitousKeyValueStoreProvider | - | 12 | prefs@4, editor@8 |
| AnimationContext | - | 56 | _viewToAnimationsMap@4, _delegate@8, _beginTime@16, _duration@24, _animationWillStartSelector@32, _animationDidStopSelector@36, _animationID@40, _context@44, _beginsFromCurrentState@48, _animationCurve@52 |
| AppleTree | Tree | 140 | availableFood@136 |
| ApportableIAP | - | 20 | _inRestoreState@13, _delegate@16 |
| ArtificialLight | DynamicObject | 104 | contributionGrid@56, addedGrid@60, maxRed@64, maxGreen@68, maxBlue@72, maxHeat@76, radius@80, contributionGridOrigin@84, diameter@92, lightDirection@96, parentObject@100 |
| AudioServicesSystemSoundPlayer | AVAudioPlayer | 88 | callback@72, callbackData@76, callbackRunLoop@80, callbackRunLoopMode@84 |
| BHClient | BHNetNode | 56 | passwordEntryAlertView@28, cachedPlayerImages@32, clientTileLoader@36, world@40, gameServerID@44, joinPassword@48, serverOwnerName@52 |
| BHMatch | - | 16 | delegate@4, host@8, port@12 |
| BHNetClientMatch | BHMatch | 79 | browser@16, domainBrowsers@20, domains@24, clientServicesWaiting@28, enetClient@32, enetPeer@36, remotePeerID@40, userName@44, photo@48, cloudKey@52, myPlayerInfo@56, playerInfos@60, … (+6) |
| BHNetNode | - | 28 | delegate@4, match@8, voiceChat@12, livePlayerInfos@16, playerInfosForAllPlayersByID@20, netNodeType@24 |
| BHNetServerMatch | BHMatch | 100 | serverPort@16, reliableServerService@20, reliableServerListeningSocket@24, enetServer@28, connections@32, persistentIdsToEnetIds@36, enetIdsToPersistentIds@40, playerInfos@44, userName@48, worldName@52, ownerName@56, cloudSalt@60, … (+7) |
| BHServer | BHNetNode | 152 | world@28, saveID@32, unapprovedClients@36, connectedClients@40, chatHistory@44, recentPlayers@48, blackList@52, curseList@56, whiteList@60, adminList@64, cloudWideAdminList@68, cloudWideInvisibleAdminList@72, … (+16) |
| BHTapView | UIView | 8 | chatView@4 |
| Bed | InteractionObject | 124 | itemType@100, beddingColor@104, tileDestructTexture@108, pillowDrawCube@112, beddingDrawCube@116, cubeShader@120 |
| BitmapFont | - | 24 | title@4, size@8, scale@12, charSet@16, bitmap@20 |
| BitmapString | - | 68 | shader@4, string@8, size@12, actualDimensions@16, horizontalAlignment@24, verticalAlignment@28, Verts@32, texCoords@36, indices@40, characterCount@44, font@48, color@52 |
| BlockAlertView | - | 22 | _blocks@4, _view@8, _height@12, viewYOffset@16, dontAnimateDismiss@20, _vignetteBackground@21 |
| BlockBackground | UIView | 9 | parentView@4, added@8 |
| BlockTextPromptAlertView | BlockAlertView | 40 | unacceptedInput@24, maxLength@28, textView@32, callBack@36 |
| Blockhead | DynamicObject | 2428 | state@56, clientID@164, clientName@168, netTextView@172, blockheadAI@176, shader@180, renderShader@184, faceShader@188, hairShader@192, bodyShader@196, clothingShader@200, headTexture@204, … (+209) |
| BlockheadAI | - | 472 | blockhead@4, world@8, foundTilePos@12, foundTile@140, previousActionTiles@156, previousActionCount@412, inactivityTimer@416, goalDigTile@420, currentSearchLevel@428, currentSearchLevelCount@432, lastFrameHadActions@436, placableItem@440, … (+7) |
| BlockheadButton | MJButton | 328 | blockhead@276, world@280, alignment@284, textView@288, progressShader@292, standardShader@296, flashShader@300, healthHeartTexture@304, smileyTexture@308, deathTexture@312, airBubbleTexture@316, flashAlpha@320, … (+1) |
| BlockheadCraftableItemObject | CraftableItemObject | 152 | name@128, skinOptions@132 |
| BlockheadPreviewView | MJView | 1332 | faceShader@60, hairShader@64, bodyShader@68, clothingShader@72, quadShader@76, headTexture@80, headHairTexture@84, headCube@88, hairCubeA@92, hairCubeB@96, bodyTexture@100, bodyCube@104, … (+60) |
| BlockheadUI | GameUIView | 200 | world@20, blockhead@24, backgroundShader@28, backgroundTexture@32, titleTextView@36, healthHeartTexture@40, smileyTexture@44, healthTextView@48, happinessTextView@52, hungerTextView@56, energyTextView@60, environmentTextView@64, … (+15) |
| Boat | DynamicObject | 144 | shader@56, texture@60, sailTexture@64, frontBackCube@68, sideCube@72, bottomCube@76, mastCube@80, sailCube@84, bodyRotation@88, prevRotation@92, goalRotationType@96, targetXSpeed@100, … (+9) |
| CAAnimation | - | 76 | _timingFunction@4, _delegate@8, _removedOnCompletion@12, _beginTime@16, _duration@24, _speed@32, _timeOffset@40, _repeatCount@48, _repeatDuration@56, _autoreverses@64, _fillMode@68, _proxy@72 |
| CAAnimationGroup | CAAnimation | 92 | _name@76, _context@80, _didStop@84, _animations@88 |
| CABasicAnimation | CAPropertyAnimation | 100 | _fromValue@88, _toValue@92, _byValue@96 |
| CADisplayLink | - | 56 | _timer@4, _impl@8, _paused@12, _suspended@13, _timestamp@16, _duration@24, _frameInterval@32, _requestedInterval@36, _adaptive@40, _frameIndex@44, _target@48, _selector@52 |
| CAEAGLLayer | CALayer | 8 | _drawableProperties@4 |
| CAEmitterCell | - | 220 | _attr@4, _state@12, _flags@16, _autoreverses@20, _beginTime@24, _duration@32, _fillMode@40, _repeatCount@44, _repeatDuration@48, _speed@56, _timeOffset@64, _enabled@72, … (+33) |
| CAEmitterLayer | CALayer | 72 | _preservesDepth@4, _emitterCells@8, _birthRate@12, _lifetime@16, _emitterZPosition@20, _emitterDepth@24, _emitterShape@28, _emitterMode@32, _renderMode@36, _velocity@40, _scale@44, _spin@48, … (+3) |
| CAGradientLayer | CALayer | 32 | _colors@4, _locations@8, _type@12, _endPoint@16, _startPoint@24 |
| CAKeyframeAnimation | CAPropertyAnimation | 124 | _values@88, _path@92, _keyTimes@96, _timingFunctions@100, _calculationMode@104, _rotationMode@108, _tensionValues@112, _continuityValues@116, _biasValues@120 |
| CALayer | - | 284 | _proxy@4, _affineTransform@8, _bounds@32, _animations@48, _zPosition@52, _savedOpacity@56, _contentsScale@60, _sublayers@64, _autoreverses@68, _beginTime@72, _duration@80, _fillMode@88, … (+27) |
| CAMediaTimingFunction | - | 20 | _c1x@4, _c1y@8, _c2x@12, _c2y@16 |
| CAPropertyAnimation | CAAnimation | 88 | _keyPath@76, _additive@80, _cumulative@81, _valueFunction@84 |
| CAScrollLayer | CALayer | 8 | _scrollMode@4 |
| CAShapeLayer | CALayer | 52 | _path@4, _fillColor@8, _strokeColor@12, _fillRule@16, _lineCap@20, _lineJoin@24, _lineDashPattern@28, _strokeStart@32, _strokeEnd@36, _lineWidth@40, _miterLimit@44, _lineDashPhase@48 |
| CATransition | CAAnimation | 96 | _type@76, _subtype@80, _startProgress@84, _endProgress@88, _filter@92 |
| CIColor | - | 16 | _color@4, _ncomps@8, _comps@12 |
| CIContext | - | 8 | _cgContext@4 |
| CLHeading | - | 56 | _timestamp@4, _magneticHeading@8, _trueHeading@16, _headingAccuracy@24, _x@32, _y@40, _z@48 |
| CLLocation | - | 68 | _coordinate@8, _altitude@24, _horizontalAccuracy@32, _verticalAccuracy@40, _course@48, _speed@56, _timestamp@64 |
| CLLocationManager | - | 56 | _networkLocationListener@4, _gpsLocationListener@8, _delegate@12, _purpose@16, _lastLocation@20, _headingOrientation@24, _distanceFilter@32, _desiredAccuracy@40, _headingFilter@48 |
| CLPlacemark | - | 68 | _location@4, _region@8, _addressDictionary@12, _name@16, _thoroughfare@20, _subThoroughfare@24, _locality@28, _subLocality@32, _administrativeArea@36, _subAdministrativeArea@40, _postalCode@44, _ISOcountryCode@48, … (+4) |
| CLRegion | - | 32 | _identifier@4, _radius@8, _center@16 |
| CMAccelerometerData | CMLogItem | 32 | _acceleration@8 |
| CMAttitude | - | 40 | _quat@8 |
| CMDeviceMotion | CMLogItem | 144 | _attitude@4, _gravity@8, _rotationRate@32, _orientation@56, _userAcceleration@80, _lastOrientation@104, _magneticField@112 |
| CMGyroData | CMLogItem | 32 | _rotationRate@8 |
| CMLogItem | - | 16 | _timestamp@8 |
| CMMagnetometerData | CMLogItem | 32 | _magneticField@8 |
| CMMotionManager | - | 97 | _internal@4, _accelerometerData@8, _gyroData@12, _magnetometerData@16, _deviceMotion@20, _accelerometerUpdateInterval@24, _gyroUpdateInterval@32, _magnetometerUpdateInterval@40, _deviceMotionUpdateInterval@48, _accelerometerActive@56, _gyroActive@57, _magnetometerActive@58, … (+11) |
| CPCache | - | 12 | cache@4, shaderCache@8 |
| CPTexture2D | - | 61 | _name@4, _size@8, _width@16, _height@20, _format@24, _maxS@28, _maxT@32, _stringSize@36, textureInfo@44, isHD@48, basePath@52, baseAlphaPath@56, … (+1) |
| CactusTree | Tree | 152 | splitHeightA@136, splitHeightB@140, splitDirection@144, availableFood@148 |
| CameraUI | GameUIView | 112 | world@20, borderLineShader@24, orthoMatrix@32, windowInfo@96, cache@100, cancelButton@104, takePhotoButton@108 |
| CaveTroll | NPC | 1124 | state@208, shader@244, renderShader@248, headTexture@252, headCube@256, bodyTexture@260, bodyCube@264, armTexture@268, armCube@272, legTexture@276, legCube@280, walkTimer@284, … (+70) |
| CharDescriptor | - | 52 | x@4, y@8, width@12, height@16, xOffset@20, yOffset@24, xAdvance@28, page@32, idNumber@36, kerningInfo@40 |
| Charset | - | 41 | size@4, lineHeight@8, base@12, width@16, height@20, pages@24, chars@28, hasKerning@40 |
| ChatView | - | 68 | delegate@4, lastKnownParentView@8, _view@12, seperator@16, visible@20, modalBackground@24, textInputBackgroundView@28, textInputView@32, chatTableView@36, headerView@40, closeButton@44, titleLabel@48, … (+5) |
| Chest | InteractionObject | 140 | inventoryItems@100, inventoryChanged@104, chestType@108, inventoryNeedsToBeSentWithUpdate@112, shelfRenderItems@116, shelfItemDataBs@132 |
| ChestUI | GameUIView | 208 | world@20, portalChestManager@24, itemsTexture@28, currentChest@32, backgroundShader@36, backgroundTexture@40, titleTextView@44, waitingDragTextView@48, orthoMatrix@64, windowInfo@128, cache@132, inventoryButtons@136, … (+18) |
| ClientTileLoader | - | 224 | world@4, client@8, saveID@12, blockDirectory@16, heightNoiseFunctionA@20, heightNoiseFunctionB@24, sandNoiseFunction@28, faultNoiseFunction@32, caveNoiseFunctionA@36, caveNoiseFunctionB@40, flintDensityNoiseFunction@44, flintDensityNoiseFunctionLegacy@48, … (+9) |
| CloudInterface | - | 144 | authenticateDelegate@4, searchDelegate@8, connectToWorldDelegate@12, createWorldDelegate@16, topupDelegate@20, reconnectAttemptQueued@24, cloudConnectionFailed@25, cloudInitialConnectionFailureReason@28, cloudChallengeConnection@32, cloudChallengeRecieveData@36, cloudURL@40, cloudAuthenticateConnection@44, … (+23) |
| ClownFish | NPC | 384 | shader@208, bodyTexture@212, tailTexture@216, sideFinTexture@220, bodyCube@224, tailCube@228, sideFinCube@232, movementDirection@236, fromSquare@240, toSquare@248, travelFraction@256, randomTimeBetweenDirectionChanges@260, … (+19) |
| ColorPicker | MJView | 88 | slider@60, colorPickerControl@64, oneBasedColor@68, colorBrightness@80, delegate@84 |
| ColorPickerControl | MJControl | 128 | shader@100, knobShader@104, knobTexture@108, oneBasedColor@112, colorBrightness@124 |
| Column | DynamicObject | 84 | itemType@56, paintColor@60, currentConfiguration@64, iceMeltTimer@68, savedDrawBuffer@72, savedDrawBufferIndex@76, animationIndex@80 |
| ControlOptionsUI | - | 132 | delegate@4, backgroundShader@8, backgroundTexture@12, titleTextView@16, blackBackgroundShader@20, orthoMatrix@32, windowInfo@96, cache@100, OKButton@104, tiltControlTextView@108, tiltControlButton@112, directControlTextView@116, … (+3) |
| CraftProgressUI | GameUIView | 220 | world@20, itemsTexture@24, backgroundShader@28, backgroundTexture@32, fuelIndicatorOn@36, fuelIndicatorOff@40, fuelButtons@44, fuelInventoryCounts@48, craftableItemBlockCubes@52, outOfFuelTextView@56, unhappyTextView@60, addFuelTextView@64, … (+22) |
| CraftUI | GameUIView | 228 | world@20, itemsTexture@24, backgroundShader@28, backgroundTexture@32, skRequest@36, doubleTimeProduct@40, priceImage@44, doubleTimePriceString@48, craftableItems@52, orthoMatrix@64, windowInfo@128, cache@132, … (+22) |
| CraftableItemObject | - | 128 | craftableItem@4 |
| CreateCustomOptionsUI | MJView | 92 | selectedOptions@60, mainTableView@64, subTableView@68, configureItemIndex@72, lineTexture@76, lineShader@80, titleTextView@84, menuBackButton@88 |
| CreateWorldUI | - | 209 | delegate@4, windowInfo@8, cache@12, cloudInterface@16, state@20, skRequest@24, creditProducts@28, locationControl@36, locationHelpButton@40, finalCancelButton@44, finalCreateButton@48, worldNameTitleTextView@52, … (+38) |
| CrystalManager | - | 21 | saveQueue@4, crystalCount@8, amountString@12, countWatcher@16, needsSave@20 |
| CustomGameRulesUI | - | 164 | world@4, parentUI@8, backgroundShader@12, backgroundTexture@16, titleTextView@20, blackBackgroundShader@24, orthoMatrix@32, windowInfo@96, cache@100, mainTableView@104, mainSelection@108, simpleSubOptionTableView@112, … (+12) |
| CustomizeBlockheadUI | GameUIView | 222 | world@20, backgroundShader@24, backgroundTexture@28, backgroundTextureColorPicker@32, orthoMatrix@48, windowInfo@112, cache@116, interactionObject@120, delegate@124, colorPicker@128, colorPickerType@132, titleTextView@136, … (+17) |
| DPad | - | 161 | world@4, shader@8, upTexture@12, downTexture@20, leftTexture@28, rightTexture@36, orthoMatrix@48, windowInfo@112, cache@116, displayed@120, touchIndex@124, leftPressed@128, … (+9) |
| Database | - | 20 | databaseEnvironment@4, env@8, dbi@12, name@16 |
| DatabaseConvertor | - | 68 | world@4, worldDatabase@8, dynamicObjectDatabase@12, blockDatabase@16, lightBlockDatabase@20, serverDatabase@24, worldDir@28, blocksDir@32, mainDirContentsToCheck@36, worldBlockDirsToCheck@40, filesToRemove@44, lightBlockFilesToRemove@48, … (+7) |
| DatabaseEnvironment | - | 16 | env@4, bulkTransaction@8, environmentDirectoryPath@12 |
| DebugLogger | - | 8 | messages@4 |
| Dodo | NPC | 369 | shader@208, nonStandardBodyShader@212, bodyTexture@216, neckTexture@220, headTexture@224, legTexture@228, footTexture@232, breedWingTexture@236, bodyCube@240, neckCube@244, headCube@248, legCube@252, … (+26) |
| Donkey | DonkeyLike | 1348 | earTexture@840, earCube@844, leftEarMatrix@848, rightEarMatrix@912, hornTexture@976, hornCube@980, hornMatrix@992, tailCubeA@1056, tailCubeB@1060, tailCubeC@1064, tailMatrixA@1072, tailMatrixB@1136, … (+7) |
| DonkeyLike | NPC | 837 | shader@208, bodyTexture@212, neckTexture@216, headTexture@220, legTexture@224, bodyCube@228, neckCube@232, headCube@236, legCube@240, babySound@244, adultSound@248, deathSound@252, … (+36) |
| Door | DynamicObject | 84 | open@53, openDirection@56, openCloseTransition@60, itemType@64, blocked@68, ironPlaceClientID@72, savedDrawBuffer@76, savedDrawBufferIndex@80 |
| DrawCube | - | 18 | vertices@4, texCoords@8, normals@12, multitexture@16, luminous@17 |
| DropBear | NPC | 424 | shader@208, bodyFrontTexture@212, bodyBackTexture@216, headTexture@220, legTexture@224, eyeTexture@228, snoutTexture@232, frontBodyCube@236, backBodyCube@240, headCube@244, snoutCube@248, eyeCube@252, … (+27) |
| DynamicObject | - | 53 | world@4, dynamicWorld@8, macroTileOwner@12, pos@16, floatPos@24, cache@32, ownerID@36, uniqueID@40, needsRemoved@48, updateNeedsToBeSent@49, creationDataNeedsToBeSent@50, unreliableUpdateNeedsToBeSent@51, … (+1) |
| DynamicWorld | - | 9528 | world@4, worldTileLoader@8, clientTileLoader@12, server@16, client@20, serverClients@24, appDatabase@28, worldDatabase@32, dynamicObjectDatabase@36, worldSaveDirectory@40, blockheads@44, netBlockheads@48, … (+54) |
| EAGLContext | - | 20 | _api@4, _sharegroup@8, _internal@12, _delayedRenderInvocations@16 |
| EAGLSharegroup | - | 8 | _private@4 |
| EAGLView | UIView | 84 | framebufferWidth@4, framebufferHeight@8, defaultFramebuffer@12, colorRenderbuffer@16, depthRenderbuffer@20, trackingTouch@24, secondaryTouch@28, gameView@32, panGestureRecognizer@36, pinchGestureRecognizer@40, tapGestureRecognizer@44, swipeGestureRecognizer@48, … (+7) |
| Egg | DynamicObject | 68 | genesDict@56, breed@60, hatchTimer@64 |
| ElevatorMotor | DynamicObject | 76 | itemType@56, availableElectricity@60, clientPowerUsage@62, minY@64, maxY@68, timeUntilNextPowerCheck@72 |
| ElevatorShaft | DynamicObject | 87 | itemType@56, lastKnownMotorPos@60, opening@68, openTimer@72, savedDrawBuffer@76, savedDrawBufferIndex@80, paintColor@84, solidTile@86 |
| EvolutionAppDelegate | - | 24 | euCheckRecieveData@4, euCheckConnection@8, gdprAccepted@12, _window@16, _viewController@20 |
| EvolutionViewController | UIViewController | 52 | context@4, animating@8, animationFrameInterval@12, displayLink@16, openGLInitialized@20, lastTime@24, gameView@32, accumulator@36, isActive@40, hasDisplayedAd@41, tempBackgroundView@44, frameHasBeenDrawnSinceActivate@48, … (+3) |
| FNImageData | - | 16 | _width@4, _height@8, _data@12 |
| FireObject | DynamicObject | 96 | burnTimer@56, spreadTimers@60, light@76, shader@80, texture@84, animationLoopIndex@88, animationLoopTimer@92 |
| FishingRod | - | 95 | world@4, blockhead@8, casting@12, lineLocations@16, hookVelocity@28, hookPos@36, nextRealInHookPos@44, isInCastingAnimation@52, castAnimationProgress@56, hookInAir@60, castingRight@61, shader@64, … (+9) |
| FlurryAnalytics | - | 21 | _apiKey@16, _suspended@20 |
| FreeBlock | DynamicObject | 156 | itemType@56, dataA@60, dataB@62, hovers@64, bounceTimer@68, fallSpeed@72, rotation@76, creationTime@80, blockCube@88, lightR@92, lightG@96, lightB@100, … (+13) |
| FreeOfferUI | - | 176 | delegate@4, tcUI@8, backgroundShader@12, backgroundTexture@16, titleTextView@20, offerTextView@24, buyButton@36, offerImage@48, blackBackgroundShader@60, noOffersTextView@64, orthoMatrix@80, windowInfo@144, … (+7) |
| FreightCar | TrainCar | 225 | platformCube@208, chestCube@212, poleCube@216, chest@220, needsChestSave@224 |
| GKAchievement | - | 32 | achievementsCallback@4, achievementReportCallback@8, showsCompletionBanner@12, completed@13, hidden@14, identifier@16, lastReportedDate@20, percentComplete@24 |
| GKAchievementDescription | - | 36 | callback@4, _hidden@8, _identifier@12, _title@16, _achievedDescription@20, _unachievedDescription@24, _maximumPoints@28, _image@32 |
| GKAchievementViewController | GKGameCenterViewController | 12 | _intentObserver@4, _achievementDelegate@8 |
| GKFriendRequestComposeViewController | UINavigationController | 8 | _composeViewDelegate@4 |
| GKGameCenterViewController | UINavigationController | 24 | _intentObserver@4, _gameCenterDelegate@8, _viewState@12, _leaderboardCategory@16, _leaderboardTimeScope@20 |
| GKImageCropOverlayView | UIView | 16 | toolbar@4, cropSize@8 |
| GKImageCropView | UIView | 28 | resizableCropArea@4, scrollView@8, imageView@12, cropOverlayView@16, xOffset@20, yOffset@24 |
| GKImageCropViewController | UIViewController | 44 | _croppedImage@4, resizeableCropArea@8, sourceImage@12, delegate@16, imageCropView@20, toolbar@24, cancelButton@28, useButton@32, cropSize@36 |
| GKImagePicker | - | 24 | resizeableCropArea@4, delegate@8, _imagePickerController@12, cropSize@16 |
| GKInvite | - | 29 | _plusGamesInvitation@4, _plusGamesRoom@8, _inviter@12, _hosted@16, _playerAttributes@20, _playerGroup@24, _fromNotification@28 |
| GKLeaderboard | - | 60 | _leaderboardsCallback@4, _scoresCallback@8, _initializedWithPlayerIDs@12, _parentBoard@16, _loading@20, _timeScope@24, _playerScope@28, _category@32, _title@36, _scores@40, _maxRange@44, _localPlayerScore@48, … (+1) |
| GKLeaderboardViewController | GKGameCenterViewController | 20 | _intentObserver@4, _leaderboardDelegate@8, _category@12, _timeScope@16 |
| GKLocalPlayer | GKPlayer | 24 | authCallback@4, _deferredLogin@8, authenticated@9, underage@10, friends@12, logoutHandler@16, _authenticateHandler@20 |
| GKMatch | - | 24 | _playerIDs@4, _delegate@8, _expectedPlayerCount@12, _roomID@16, _room@20 |
| GKMatchRequest | - | 36 | minPlayers@4, maxPlayers@8, playerGroup@12, playerAttributes@16, playersToInvite@20, defaultNumberOfPlayers@24, inviteMessage@28, _inviteeResponseHandler@32 |
| GKMatchmaker | - | 20 | _findMatchCallbackBlock@4, _inviteHandlerBlock@8, _currentInvitation@12, _match@16 |
| GKMatchmakerViewController | UINavigationController | 24 | _matchRequest@4, _invite@8, _hosted@12, _matchmakerDelegate@16, defaultInvitationMessage@20 |
| GKMatchmakerViewControllerPlaceholderView | UIView | 8 | _matchmakerViewController@4 |
| GKPlayer | - | 20 | _playerID@4, _alias@8, _isFriend@12, _displayName@16 |
| GKResizeableCropOverlayView | GKImageCropOverlayView | 56 | _initialContentSize@4, _resizingEnabled@12, _theAnchor@16, _startPoint@24, _resizeMultiplyer@32, _contentView@48, _cropBorderView@52 |
| GKScore | - | 48 | _shouldSetDefaultLeaderboard@4, _formattedValue@8, _category@12, _date@16, _playerID@20, _rank@24, _value@32, _context@40 |
| GKSession | - | 40 | _session@4, _available@8, _delegate@12, _sessionID@16, _displayName@20, _sessionMode@24, _peerID@28, _disconnectTimeout@32 |
| GKVoiceChat | - | 24 | _active@4, _playerStateUpdateHandler@8, _name@12, _volume@16, _playerIDs@20 |
| GLKBaseEffect | - | 96 | _colorMaterialEnabled@4, _fogEnabled@5, _transform@8, _lightingType@12, _light0@16, _light1@20, _light2@24, _material@28, _texture2d0@32, _texture2d1@36, _textureOrder@40, _constantColor@48, … (+5) |
| GLKEffectProperty | - | 16 | _location@4, _nameString@8, _prv@12 |
| GLKEffectPropertyFog | GLKEffectProperty | 60 | _enabled@16, _mode@20, _color@32, _density@48, _start@52, _end@56 |
| GLKEffectPropertyLight | GLKEffectProperty | 132 | _enabled@16, _position@32, _ambientColor@48, _diffuseColor@64, _specularColor@80, _spotDirection@96, _spotExponent@108, _spotCutoff@112, _constantAttenuation@116, _linearAttenuation@120, _quadraticAttenuation@124, _transform@128 |
| GLKEffectPropertyMaterial | GLKEffectProperty | 84 | _ambientColor@16, _diffuseColor@32, _specularColor@48, _emissiveColor@64, _shininess@80 |
| GLKEffectPropertyTexture | GLKEffectProperty | 32 | _enabled@16, _name@20, _target@24, _envMode@28 |
| GLKEffectPropertyTransform | GLKEffectProperty | 180 | _modelviewMatrix@16, _projectionMatrix@80, _normalMatrix@144 |
| GLKReflectionMapEffect | GLKBaseEffect | 112 | _textureCubeMap@72, _matrix@76 |
| GLKSkyboxEffect | - | 40 | _center@4, _xSize@16, _ySize@20, _zSize@24, _textureCubeMap@28, _transform@32, _label@36 |
| GLKTextureInfo | - | 32 | containsMipmaps@4, name@8, target@12, width@16, height@20, alphaState@24, textureOrigin@28 |
| GLKView | UIView | 40 | _enableSetNeedsDisplay@4, _delegate@8, _context@12, _drawableWidth@16, _drawableHeight@20, _drawableColorFormat@24, _drawableDepthFormat@28, _drawableStencilFormat@32, _drawableMultisample@36 |
| GLKViewController | UIViewController | 72 | colorRenderbuffer@4, depthRenderbuffer@8, framebuffer@12, displayLink@16, paused@20, pauseOnWillResignActive@21, resumeOnDidBecomeActive@22, delegate@24, preferredFramesPerSecond@28, framesPerSecond@32, framesDisplayed@36, timeSinceFirstResume@40, … (+3) |
| GameUIView | - | 17 | displayed@4, displayStartAnimationTimer@8, displayStartScale@12, resourcesLoaded@16 |
| GameView | - | 520 | viewController@4, glView@8, cache@12, basicShader@16, mainMenuUI@20, world@24, instructionsViewController@28, appDatabaseEnvironment@32, appDatabase@36, bhClient@40, bhServer@44, projectionMatrix@48, … (+100) |
| GatherBlock | DynamicObject | 64 | timer@56, lastKnownGatherValue@60 |
| GemTree | Tree | 144 | gemTreeType@136, fruitYear@140 |
| GlowBlock | DynamicObject | 64 | light@56, tileType@60 |
| HZAdBase | - | 8 | _delegate@4 |
| HZBannerAd | UIView | 16 | _delegate@4, _options@8, _mediatedNetwork@12 |
| HZBannerAdOptions | - | 48 | _facebookBannerSize@4, _admobBannerSize@8, _presentingViewController@12, _tag@16, _heyzapExchangeBannerSize@20, _inMobiBannerSize@28, _fetchTimeout@40 |
| HandCar | TrainCar | 248 | platformCube@208, poleCube@212, pivotCube@216, handleCube@220, externalXAcceleration@224, riderAnimationTimer@228, railSound@232, trackingAir@236, airTrackStartPos@240 |
| HungerUI | GameUIView | 180 | world@20, blockhead@24, backgroundShader@28, backgroundTexture@32, itemsTexture@36, type@40, firstTextView@44, secondTextView@48, thirdTextView@52, eatTextView@56, eatNumberTextView@60, foodImage@64, … (+11) |
| InstructionsViewController | UIViewController | 48 | gameView@4, isServerScreen@8, allowEdit@9, worldName@12, worldSummaryString@16, welcomeMessage@20, contentView@24, webView@28, titleBar@32, editView@36, editViewController@40, editTitleBar@44 |
| InteractionObject | DynamicObject | 97 | currentBlockhead@56, shader@60, texture@64, isInUse@68, flipped@69, remoteBlockheadInUseUniqueID@72, savedBlockheadIndex@80, ownerName@84, paintColor@88, proxyObjectOwner@92, needsToBeRemovedWhenInteractionEnds@96 |
| InventoryButton | MJButton | 404 | world@276, alignment@280, textView@284, subItemsVisibleTitleView@288, countText@292, topLevel@296, subButtons@300, startTouchSubButtonIndex@304, selectedButton@308, tappedSubButton@312, selectedButtonWasTapped@316, currentItem@320, … (+22) |
| InventoryFullUI | GameUIView | 144 | world@20, blockhead@24, backgroundShader@28, backgroundTexture@32, orthoMatrix@48, windowInfo@112, cache@116, translationOffset@120, pos@128, titleTextView@136, descriptionTextView@140 |
| InventoryItem | - | 24 | itemType@4, dataA@8, dataB@10, subItems@12, selectedSubItemIndex@16, dynamicObjectSaveDict@20 |
| JetPackUI | GameUIView | 152 | world@20, itemsTexture@24, backgroundShader@28, backgroundTexture@32, fuelIndicatorOn@36, fuelIndicatorOff@40, addFuelButton@44, freeFlightButton@48, fuelCountText@52, orthoMatrix@64, windowInfo@128, cache@132, … (+3) |
| JoinWorldUI | - | 180 | delegate@4, windowInfo@8, cache@12, cloudInterface@16, state@20, disabledTextView@24, advancedButton@28, joinRandomButton@32, finalCancelButton@36, finalJoinButton@40, nickNameTitleTextView@44, nickNameButton@48, … (+32) |
| KelpPlant | Plant | 204 | checkWeatherCount@100, killCount@104, aboveGatherProgress@108, waveTimer@172, growthTimer@176, availableFood@180, savedDrawBuffers@184, savedDrawBufferIndexes@192, numberOfOccupiedTilesAbove@200 |
| Ladder | DynamicObject | 62 | itemType@56, paintColor@60 |
| LoadWorldUI | - | 168 | delegate@4, windowInfo@8, cache@12, cloudInterface@16, playButton@20, optionsButton@24, blockheadNamesTextView@28, blockheadPreviews@32, gameSave@36, state@40, textEntryType@44, backButton@48, … (+29) |
| MJButton | MJControl | 273 | title@100, titleAlignment@104, shader@108, backgroundTexture@112, backgroundSelectedTexture@116, backgroundHighlightedTexture@120, backgroundHighlightedSelectedTexture@124, titleView@128, glyphTexture@132, glyphFrame@136, glyphColor@152, isSelected@168, … (+22) |
| MJColorWell | MJControl | 109 | shader@100, frameTexture@104, isSelected@108 |
| MJControl | MJView | 100 | target@60, action@64, hover@68, wasClicked@69, receivedTouchStart@70, enabled@71, sendsEventOnTouchStart@72, clickSound@76, eventFrame@80, startTouchAnimationTimer@96 |
| MJImageView | MJView | 85 | shader@60, texture@64, minTexX@68, maxTexX@72, minTexY@76, maxTexY@80, customTexCoords@84 |
| MJMultiSound | - | 80 | _sounds@4, _fileName@8, _maxPlaybacks@12, _looping@16, _volume@20, _volumeMultipier@24, _pitch@28, _basePitch@32, _fileNames@36, soundIndex@40, lastPlayTime@48, randomPitchOffset@56, … (+5) |
| MJProgressBar | MJView | 84 | shader@60, progress@64, checkMarkCount@68, checkMarkVerts@72, red@76, dots@80 |
| MJSegmentedControl | MJControl | 128 | titles@100, shader@104, backgroundTexture@108, backgroundSelectedTexture@112, titleViews@116, selectedIndex@120, titleYOffset@124 |
| MJSlider | MJControl | 152 | shader@100, backgroundTexture@104, knobTexture@108, value@112, descreteValue@116, descrete@120, descreteMin@124, descreteMax@128, knobColor@132, completionAction@148 |
| MJSound | - | 89 | _data@4, _localFormat@8, _format@12, _frequency@16, _buffer@20, bufferRetainCount@24, _source@28, _looping@32, _paused@33, _volume@36, _volumeMultipier@40, _file@44, … (+13) |
| MJSoundManager | - | 115 | loadedSounds@4, loadedMultiSounds@8, loadedSoundsArray@12, externalMultiSounds@16, appActivePausedSounds@20, otherAudioWasPaying@24, device@28, alContext@32, silentSwitchWasOnDuringLaunch@36, stopMP3time@40, playingURL@48, soundVolume@52, … (+18) |
| MJTextView | MJView | 76 | text@60, string@64, font@68, horizontalAlignment@72 |
| MJToggleButton | MJButton | 274 | on@273 |
| MJView | - | 57 | hidden@4, frame@8, alpha@24, color@28, subviews@44, cache@48, windowInfo@52, ignoreEvents@56 |
| MPMediaItemCollection | MPMediaEntity | 20 | _items@4, _count@8, _mediaTypes@12, _representativeItem@16 |
| MPMediaPickerController | UIViewController | 24 | _internal@4, _allowsPickingMultipleItems@8, _prompt@12, _mediaTypes@16, _delegate@20 |
| MPMediaPropertyPredicate | MPMediaPredicate | 16 | _property@4, _value@8, _comparisonType@12 |
| MPMediaQuery | - | 28 | _filterPredicates@4, _items@8, _collections@12, _groupingType@16, _itemSections@20, _collectionSections@24 |
| MPMediaView | UIView | 16 | shouldAutoplay@4, initialPlaybackTime@8 |
| MPMoviePlayerController | - | 44 | _movieSourceType@4, shouldAutoplay@8, useApplicationAudioSession@9, fullscreen@10, contentURL@12, view@16, backgroundView@20, playbackState@24, loadState@28, controlStyle@32, repeatMode@36, scalingMode@40 |
| MPMoviePlayerViewController | UIViewController | 8 | moviePlayer@4 |
| MPVolumeView | UIView | 6 | _showsVolumeSlider@4, _showsRouteButton@5 |
| MainMenuOptionsUI | - | 152 | delegate@4, soundOptionsUI@8, controlOptionsUI@12, needsToDismissSoundOptions@16, needsToDismissControlOptions@17, backgroundShader@20, backgroundTexture@24, titleTextView@28, blackBackgroundShader@32, orthoMatrix@48, windowInfo@112, cache@116, … (+8) |
| MainMenuUI | - | 513 | delegate@4, cloudInterface@8, backgroundShader@12, starShader@16, coloredTexturedShader@20, coloredNoTextureShader@24, backgroundTexture@28, clockTexture@32, clockHandTexture@36, titleTextView@40, tileTexture@44, mainMenuOptionsUI@48, … (+57) |
| MapUI | - | 180 | world@4, backgroundShader@8, backgroundTexture@12, blackBackgroundShader@16, mapShader@20, orthoMatrix@32, windowInfo@96, cache@100, mapDir@104, loadedTextures@108, texturesToLoad@120, scroll@132, … (+8) |
| MultiplayerWorldOptionsUI | - | 184 | world@4, optionsUI@8, addCreditUI@12, addCreditUINeedsDismissed@16, needsToDismissCustomRules@17, customRulesOnlyMode@18, backgroundShader@20, backgroundTexture@24, titleTextView@28, blackBackgroundShader@32, orthoMatrix@48, windowInfo@112, … (+17) |
| NNNativeCreative | - | 36 | _branded@4, _persistent@5, _identifier@8, _type@12, _positiveAction@16, _positiveText@20, _negativeText@24, _order@28, _contents@32 |
| NNSupportResponse | - | 16 | _supportId@4, _message@8, _identifiers@12 |
| NPC | DynamicObject | 208 | damage@54, dead@56, visible@57, killBlockhead@60, hitForce@64, fullness@68, tameCooldownTimer@72, mateCooldownTimer@76, layTimer@80, layCooldownTimer@84, age@88, name@92, … (+28) |
| NSLayoutConstraint | - | 40 | _shouldBeArchived@4, _priority@8, _constant@12, _firstItem@16, _firstAttribute@20, _relation@24, _secondItem@28, _secondAttribute@32, _multiplier@36 |
| NSParagraphStyle | - | 60 | _lineSpacing@4, _paragraphSpacing@8, _alignment@12, _headIndent@16, _tailIndent@20, _firstLineHeadIndent@24, _minimumLineHeight@28, _maximumLineHeight@32, _lineBreakMode@36, _baseWritingDirection@40, _lineHeightMultiple@44, _paragraphSpacingBefore@48, … (+2) |
| NSStringDrawingContext | - | 44 | _verticallyCenterWhileDrawing@4, _minimumScaleFactor@8, _actualScaleFactor@12, _maximumLineCount@16, _minimumTrackingAdjustment@20, _actualTrackingAdjustment@24, _totalBounds@28 |
| NavigateButtons | MJControl | 120 | value@100, count@104, leftButton@108, rightButton@112, textView@116 |
| NetPlayerButton | MJButton | 328 | standardShader@276, world@280, worldUI@284, alignment@288, playerUI@292, avatarImage@296, mutedImage@300, hasAvatar@304, local@305, playerID@308, playerName@312, textChatEnabled@316, … (+6) |
| NetPlayerUI | - | 76 | netPlayerButton@4, backgroundShader@8, backgroundTexture@12, textToggleTextView@16, textToggleButton@20, muteButton@24, reportButton@28, kickButton@32, banButton@36, playerTitle@40, teamText@44, windowInfo@48, … (+6) |
| NewBlockheadUI | GameUIView | 228 | world@20, backgroundShader@24, backgroundTexture@28, textEntryAlertView@32, orthoMatrix@48, windowInfo@112, cache@116, workbench@120, blockhead@124, customizeBlockheadUI@128, incomingCraftableItemObject@132, titleTextView@136, … (+13) |
| NoiseFunction | - | 12 | _tileable@4, _structPtr@8 |
| NoodleBackHandler | - | 16 | _exitMessage@4, _handlers@8, _currentState@12 |
| NoodleGPSignInManager | - | 8 | _callback@4 |
| NoodleNewsClientInstance | - | 12 | javaDelegate@4, _delegate@8 |
| NoodlePermissionGranter | - | 20 | privateDelegate@16 |
| NormalPlant | Plant | 132 | shader@100, texture@104, tileDestructTexture@108, checkWeatherCount@112, killCount@116, availableFood@120, light@124, lastLightFactor@128 |
| OptionsUI | - | 151 | world@4, pauseUI@8, backgroundShader@12, backgroundTexture@16, titleTextView@20, blackBackgroundShader@24, orthoMatrix@32, windowInfo@96, cache@100, OKButton@104, hdTexturesTextView@108, hdTexturesButton@112, … (+11) |
| OwnershipAreaRenderer | - | 24 | world@4, cache@8, borderTexture@12, borderShader@16, displayTimer@20 |
| OwnershipSign | Sign | 140 | landOwnerID@124, landOwnerName@128, widthRadius@132, heightRadius@136 |
| OwnershipSignUI | GameUIView | 204 | world@20, currentSign@24, scrollButtonsFrame@28, backgroundShader@44, backgroundTexture@48, titleTextView@52, orthoMatrix@64, windowInfo@128, cache@132, translationOffset@136, playerButtons@144, players@148, … (+15) |
| PaintMixUI | GameUIView | 216 | world@20, backgroundShader@24, backgroundTexture@28, orthoMatrix@32, windowInfo@96, cache@100, workbench@104, blockhead@108, incomingCraftableItemObject@112, titleTextView@116, craftButton@120, numberCanCraftTextView@124, … (+16) |
| Painting | DynamicObject | 80 | itemType@56, imageData@60, ownerName@64, shader@68, texture@72, textureLoadedIsHD@76, hiddenDueToServerBan@77, hidden@78, hasVerifiedImageData@79 |
| PaintingCraftableItemObject | CraftableItemObject | 136 | imageData@128, outputImageData@132 |
| ParticleEmitter | - | 108 | world@4, particles@8, noiseFunction@12, freeIndices@16, takenIndices@20, glData@24, shader@28, cameraMinXWorld@32, cameraMaxXWorld@36, cameraMinYWorld@40, cameraMaxYWorld@44, electrictyParticles@48, … (+14) |
| PassengerCar | TrainCar | 228 | platformCube@208, poleCube@212, longWallCube@216, shortWallCube@220, roofCube@224 |
| PathCreator | - | 96 | world@4, pathUser@8, goalX@12, goalY@16, goalInteraction@20, pathType@24, extraData@28, openList@32, closedList@36, closestDistance@40, startIndex@44, inProgress@48, … (+10) |
| PauseUI | - | 139 | world@4, optionsUI@8, shareUI@12, backgroundShader@16, backgroundTexture@20, titleTextView@24, blackBackgroundShader@28, orthoMatrix@32, windowInfo@96, cache@100, exitButton@104, tcButton@108, … (+9) |
| PetUI | GameUIView | 148 | world@20, npc@24, backgroundShader@28, backgroundTexture@32, titleTextView@36, breedTextView@40, healthTextView@44, hungerTextView@48, nameEditButton@52, setFreeButton@56, progressShader@60, orthoMatrix@64, … (+4) |
| PineTree | Tree | 140 | availableFood@136 |
| Plant | DynamicObject | 100 | maxAgeGene@54, growthRateGene@56, treeDensityNoiseFunction@60, seasonOffsetNoiseFunction@64, seasonOffset@68, age@72, frozen@76, gatherProgress@80, hasFloweredThisSeason@84, flowering@85, maxAge@88, growthRate@92, … (+1) |
| PlusGamesManager | - | 48 | achievementsCache@16, connecting@20, delegate@24, roomDelegate@28, messageDelegate@32, inviteDelegate@36, selectPlayersDelegate@40, disconnectedDelegate@44 |
| PortalChestManager | - | 20 | world@4, portalChestInventoryItems@8, pendingTransaction@12, pendingTransactionIsResend@13, transactionIdentifierCount@14, pendingSaveData@16 |
| ProjectileManager | - | 32 | world@4, cache@8, texture@12, shader@16, projectiles@20 |
| Rail | DynamicObject | 66 | itemType@56, currentConfiguration@60, drawPoles@64, ownedByStation@65 |
| Reachability | - | 12 | _alwaysReturnLocalWiFiStatus@4, _reachabilityRef@8 |
| RegenerateUI | GameUIView | 140 | world@20, backgroundShader@24, backgroundTexture@28, orthoMatrix@32, windowInfo@96, cache@100, blockhead@104, titleTextView@108, descriptionTextView@112, progressShader@116, dieButton@120, completeButton@124, … (+2) |
| SKPayment | - | 20 | _productIdentifier@4, _productType@8, _quantity@12, _requestData@16 |
| SKPaymentQueue | - | 8 | _internal@4 |
| SKPaymentQueueInternal | - | 52 | _queue@4, _observers@8, _transactionFile@12, _iap@16, _paymentTransactions@20, _purchasingTransactions@24, _restoredTransactions@28, _deferredObserverQueue@32, _deferredRemovedQueue@36, _changeLock@40, _setupFinished@44, _subscriptionsSupportedBlocks@48 |
| SKPaymentTransaction | - | 56 | _transaction@4, _error@8, _originalTransaction@12, _payment@16, _transactionDate@20, _transactionIdentifier@24, _transactionReceipt@28, _transactionState@32, _startId@36, _statefulInternalTransactionIdentifer@40, _googleIABV3Token@44, _purchaseToken@48, … (+1) |
| SKProduct | - | 9 | _internal@4, _downloadable@8 |
| SKProductInternal | - | 48 | _product@4, _localizedDescription@8, _localizedTitle@12, _price@16, _priceString@20, _priceMicrosString@24, _priceCurrencyCode@28, _originalPriceString@32, _priceLocale@36, _productIdentifier@40, _productType@44 |
| SKProductsRequest | SKRequest | 20 | _productsRequestInternal@8, _identifiers@12, _lowercaseIdentifiers@16 |
| SKProductsRequestInternal | - | 12 | _request@4, _identifiers@8 |
| SKProductsResponse | - | 8 | _internal@4 |
| SKProductsResponseInternal | - | 16 | _response@4, _products@8, _invalidProductIdentifiers@12 |
| SKRequest | - | 8 | _requestInternal@4 |
| SKRequestInternal | - | 12 | _request@4, _delegate@8 |
| SKStoreProductViewController | UIViewController | 8 | delegate@4 |
| Scorpion | NPC | 360 | shader@208, bodyTexture@212, legTexture@216, bodyCube@220, tailCubeA@224, tailCubeB@228, tailCubeC@232, tailCubeD@236, legCube@240, armCube@244, movementDirection@248, fromSquare@252, … (+23) |
| ScrollingButtons | MJView | 122 | world@60, craftUI@64, workbench@68, craftableItemButtons@72, craftableBooleans@76, craftableCounts@80, selectedCraftButtonIndex@84, lockImages@88, upgradeImages@92, secondaryIndicatorItemTypes@96, craftableItemBlockCubesOrItemTypes@100, xScroll@104, … (+5) |
| ScrollingButtonsPaint | MJView | 107 | paintMixUI@60, workbench@64, pigmentButtons@68, pigmentBooleans@72, inventoryCounts@76, selectedPigmentButtonIndex@80, itemsTexture@84, xScroll@88, scrollVelocity@92, lastX@96, startX@100, scrollInProgress@104, … (+2) |
| ScrollingButtonsTradePortal | MJView | 110 | world@60, tradePortalUI@64, tradePortal@68, itemButtons@72, selectedButtonIndex@76, itemsTexture@80, upgradeImageView@84, itemBlockCubesOrItemTypes@88, xScroll@92, scrollVelocity@96, lastX@100, startX@104, … (+2) |
| ScrollingListTradePortal | MJView | 208 | world@60, tradePortalUI@64, tradePortal@68, lineTexture@72, paintShader@76, items@80, yScroll@84, scrollVelocity@88, lastY@92, startY@96, scrollInProgress@100, startTouchWasInView@101, … (+8) |
| ScrollingNetPlayerButtons | MJView | 105 | world@60, worldUI@64, playerButtons@68, chatButton@72, scroll@76, scrollVelocity@80, lastX@84, startX@88, lastY@92, startY@96, scrollInProgress@100, startTouchWasInView@101, … (+3) |
| SearchResultsUI | MJView | 112 | delegate@60, coloredNoTextureShader@64, resultButtons@68, results@72, resultPlayerCounts@76, resultOwners@80, selectedButton@84, yScroll@88, scrollVelocity@92, lastY@96, startY@100, scrollInProgress@104, … (+2) |
| ServerClient | - | 92 | clientID@4, server@8, requestedBlockIndices@12, requestedBlockRequestTypes@16, wiredBlocks@28, wiredDynamicObjects@32, creationArraysToSend@36, updateArraysToSend@40, creationDataUpdateArraysToSend@44, updateUnreliableArraysToSend@48, removalArraysToSend@52, requestsHeartBeat@56, … (+11) |
| Shader | - | 12 | program@4, uniformLocations@8 |
| ShakeMotionDetectionDelegate | - | 40 | motionManager@4, accel@8, currentAccel@16, lastAccel@24, savedTimeInterval@32 |
| ShareUI | - | 144 | world@4, pauseUI@8, backgroundShader@12, backgroundTexture@16, titleTextView@20, blackBackgroundShader@24, orthoMatrix@32, windowInfo@96, cache@100, OKButton@104, shareAppButton@108, inviteToWorldButton@112, … (+7) |
| Shark | NPC | 412 | shader@208, bodyFrontTexture@212, bodyBackTexture@216, headTopTexture@220, headBottomTexture@224, topFinTexture@228, sideFinTexture@232, tailFinTopTexture@236, tailFinBottomTexture@240, bodyFrontCube@244, bodyBackCube@248, headTopCube@252, … (+36) |
| Sign | InteractionObject | 121 | text@100, bitmapString@104, tileDestructTexture@108, connectionType@112, offsetType@116, blackText@120 |
| SleepProgressUI | GameUIView | 141 | world@20, backgroundShader@24, backgroundTexture@28, orthoMatrix@32, windowInfo@96, cache@100, blockhead@104, titleTextView@108, energyTextView@112, progressShader@116, abortButton@120, completeButton@124, … (+3) |
| SnowSurfaceBlock | DynamicObject | 72 | temperature@56, partialContent@60, saveDictCached@64, rainRandomTimer@68 |
| SoundOptionsUI | - | 124 | delegate@4, backgroundShader@8, backgroundTexture@12, titleTextView@16, blackBackgroundShader@20, orthoMatrix@32, windowInfo@96, cache@100, OKButton@104, musicVolumeTextView@108, musicSlider@112, soundVolumeTextView@116, … (+1) |
| Stairs | DynamicObject | 84 | itemType@56, currentConfiguration@60, paintColor@64, iceMeltTimer@68, savedDrawBuffer@72, savedDrawBufferIndex@76, animationIndex@80 |
| SteamTrain | TrainCar | 327 | boilerCube@208, wheelRodCube@212, frontGrillCube@216, driverCabCube@220, chimneyCube@224, backWallCube@228, roofCube@232, roofPoleCube@236, doorCube@240, steamSound@244, railSound@248, goingRight@252, … (+17) |
| SurfaceBlock | DynamicObject | 64 | lastSaveContent@56, pingPong@60, currentlyRequiresPhysicalBlock@61, removeNextFrame@62, removeNextFrameEmpty@63 |
| TCUI | - | 200 | delegate@4, freeOfferUI@8, skRequest@12, backgroundShader@16, backgroundTexture@20, titleTextView@24, purchasingTextView@28, buyableTitleTextView@32, quantityTitleTextView@48, buyButton@64, priceImage@80, freeOffersTextView@96, … (+11) |
| TableSelectionAlertView | - | 24 | _view@4, _blocks@8, _height@12, tableView@16, options@20 |
| TableViewUI | MJView | 108 | dataSource@60, optionButtons@64, optionExtraControls@68, selectedIndex@72, buttonsNeedUpdating@76, needsToScrollSelectionToVisible@77, yScroll@80, scrollVelocity@84, lastY@88, startY@92, scrollInProgress@96, startTouchWasInView@97, … (+3) |
| TipManager | - | 44 | world@4, currentTipText@8, timeoutTimer@12, timeLastSecondBlockheadTipDisplayed@16, tipColor@24, tutorialTipText@40 |
| Torch | DynamicObject | 92 | light@56, connectionType@60, itemType@64, animationLoopIndex@68, animationLoopTimer@72, animates@76, flatOnSideAndBottom@77, chandelier@78, dataA@80, dataB@82, savedDrawBuffer@84, savedDrawBufferIndex@88 |
| TradeMissionItem | - | 133 | world@4, windowInfo@8, cache@12, blockhead@16, tradePortal@20, mission@24, lineTexture@56, lineShader@60, frame@64, rewardTitleTextView@80, rewardItemTextView@84, needTextView@88, … (+11) |
| TradeMissionManager | - | 77 | world@4, appDatabase@8, missionsConnection@12, missionsRecieveData@16, activeOrCompletedMissions@20, checkForCompletedMissionsTimer@24, serverResponseTime@32, localTimeAtServerResponse@40, valid@48, connectionFailed@49, MISSION_COUNTS@52, delegate@72, … (+1) |
| TradeMissionUI | GameUIView | 172 | world@20, backgroundShader@24, backgroundTexture@28, orthoMatrix@32, windowInfo@96, cache@100, frame@104, yScroll@120, scrollVelocity@124, lastY@128, startY@132, scrollInProgress@136, … (+8) |
| TradePortal | InteractionObject | 138 | light@100, animationLoopTimer@104, animationLoopIndex@108, sound@112, paused@116, savedDrawBuffer@120, savedDrawBufferIndex@124, localPriceOffsets@128, level@132, isSellInteraction@136, isMissionInteraction@137 |
| TradePortalBuySellButton | MJButton | 292 | listedPrice@276, listedCount@280, itemType@284, usageMultiplier@288 |
| TradePortalGraph | MJView | 108 | world@60, tradePortalUI@64, tradePortal@68, startTouchWasInView@72, getPricesConnection@76, getPricesRecieveData@80, priceArrayToDraw@84, priceGraphTexture@88, priceGraphImage@92, titleTextView@96, loadingTextView@100, exitButton@104 |
| TradePortalItem | - | 73 | scrollingListTradePortal@4, world@8, tradePortal@12, cache@16, windowInfo@20, priceTextView@24, buySellButton@28, buyStackButton@32, graphButton@36, lockImage@40, countText@44, lineTexture@48, … (+6) |
| TradePortalUI | GameUIView | 192 | world@20, itemsTexture@24, backgroundShader@28, backgroundTexture@32, backgroundTextureUpgrade@36, orthoMatrix@48, windowInfo@112, cache@116, tradePortal@120, blockhead@124, graphView@128, titleTextView@132, … (+13) |
| TradingPost | InteractionObject | 127 | sellSlot@100, coinCount@104, priceTier@108, sellerClientName@112, usageShader@116, bitmapString@120, needsToUpdateBitmapString@124, inventoryNeedsToBeSentWithUpdate@125, blackText@126 |
| TradingPostBuyUI | GameUIView | 196 | world@20, currentTradingPost@24, backgroundShader@28, backgroundTexture@32, titleTextView@36, forSaleTextView@40, itemTextView@44, itemTypeOrBlock@48, itemBlockXOffset@52, eachTitleTextView@56, eachCostTextView@60, totalTitleTextView@64, … (+15) |
| TradingPostSellUI | GameUIView | 212 | world@20, currentTradingPost@24, backgroundShader@28, backgroundTexture@32, titleTextView@36, waitingDragTextView@40, collectProfitsFirstTextView@44, priceTextView@48, priceTitleTextView@52, profitTextView@56, profitAmountTextView@60, orthoMatrix@64, … (+21) |
| TrainCar | DynamicObject | 208 | shader@56, worldObjectShader@60, tileTexture@64, tileDestructTexture@68, itemTexture@72, riders@76, savedBlockheadIndex@84, rotationAnimationTimer@92, leftWheelPos@96, rightWheelPos@104, leftWheelVel@112, rightWheelVel@120, … (+13) |
| TrainStation | InteractionObject | 132 | cubeShader@100, signShader@104, tileDestructTexture@108, platformBlock@112, poleDrawCube@116, bitmapString@120, needsToUpdateBitmapString@124, text@128 |
| Tree | DynamicObject | 136 | maxHeightGene@54, growthRateGene@56, height@60, maxHeightReached@64, growthCounter@68, growthRate@72, treeDensityNoiseFunction@76, seasonOffsetNoiseFunction@80, treeSeasonOffset@84, maxHeight@88, maxAge@92, age@96, … (+7) |
| TulipPlant | Plant | 164 | availableFood@100, checkWeatherCount@104, killCount@108, colorGenes@112, mixGenes@114, mateColorGenes@116, topColor@120, bottomColor@136, shader@152, texture@156, randomRotation@160 |
| Tutorial | - | 22 | timer@4, world@8, state@12, impromptuNightState@16, wrongToolHasBeenDisplayed@20, needsToRestoreToLatestAlertAfterReload@21 |
| UIAcceleration | - | 40 | _timestamp@8, _x@16, _y@24, _z@32 |
| UIAccelerometer | - | 24 | _accelerometerDidAccelerate@4, _enabled@5, _active@6, _delegate@8, updateInterval@16 |
| UIAccessibility | - | 72 | isAccessibilityElement@4, accessibilityElementsHidden@5, accessibilityViewIsModal@6, shouldGroupAccessibilityChildren@7, accessibilityLabel@8, accessibilityHint@12, accessibilityValue@16, accessibilityPath@20, accessibilityLanguage@24, focus@28, activation@32, accessibilityTraits@40, … (+2) |
| UIActionSheet | UIView | 36 | _visible@4, actionSheetStyle@8, cancelButtonIndex@12, destructiveButtonIndex@16, firstOtherButtonIndex@20, _delegate@24, _title@28, _numberOfButtons@32 |
| UIActivityIndicatorView | UIView | 20 | _style@4, _animating@8, _hidesWhenStopped@9, _activityIndicatorViewStyle@12, _color@16 |
| UIActivityItemProvider | - | 12 | activityType@4, placeholderItem@8 |
| UIActivityViewController | UIViewController | 12 | completionHandler@4, excludedActivityTypes@8 |
| UIAlertView | UIView | 48 | _delegate@4, _title@8, _message@12, _cancel@16, _buttons@20, _textFields@24, _visible@28, _alertViewStyle@32, _context@36, _hasDeliveredClick@40, _modalViewFlags@44 |
| UIApplication | UIResponder | 88 | _delegate@4, _keyWindow@8, _statusBarFrame@12, _windows@28, _statusBarOrientationAnimationDuration@32, _idleTimerDisabled@40, _applicationIconBadgeNumber@44, _supportedOrientations@48, _networkActivityIndicatorVisible@49, _applicationSupportsShakeToEdit@50, _ignoringInteraction@51, _rootObjects@52, … (+7) |
| UIBarButtonItem | UIBarItem | 36 | _style@4, _customView@8, _systemId@12, _action@16, _target@20, _width@24, _possibleTitles@28, _tintColor@32 |
| UIBarItem | - | 60 | _toolbar@4, _enabled@8, _title@12, _image@16, _landscapeImagePhone@20, _tag@24, _imageInsets@28, _landscapeImagePhoneInsets@44 |
| UIBezierPath | - | 49 | _path@4, _lineDashPattern@8, _lineDashPatternCount@12, _lineWidth@16, _miterLimit@20, _flatness@24, _lineDashPhase@28, _lineCapStyle@32, _lineJoinStyle@36, _usesEvenOddFillRule@40, _immutablePath@44, _immutablePathIsValid@48 |
| UIButton | UIControl | 104 | _contentEdgeInsets@4, _titleEdgeInsets@20, _imageEdgeInsets@36, _titleView@52, _imageForState@56, _backgroundImageForState@60, _titleColorForState@64, _titleForState@68, _titleShadowColorForState@72, _initialized@76, _buttonFlags@80, _eligibleForTap@84, … (+5) |
| UIButtonContent | - | 36 | title@4, attributedTitle@8, image@12, background@16, titleColor@20, imageColor@24, shadowColor@28, drawingStroke@32 |
| UIButtonEvent | UIEvent | 24 | _subtype@4, _code@8, _timestamp@16 |
| UIButtonImage | UIImageView | 8 | _button@4 |
| UIButtonTitle | UILabel | 8 | _button@4 |
| UIClassSwapper | - | 12 | className@4, object@8 |
| UICollectionReusableView | UIView | 20 | _layoutAttributes@4, _reuseIdentifier@8, _collectionView@12, _reusableViewFlags@16 |
| UICollectionView | UIScrollView | 196 | _layout@4, _dataSource@8, _backgroundView@12, _indexPathsForSelectedItems@16, _cellReuseQueues@20, _supplementaryViewReuseQueues@24, _decorationViewReuseQueues@28, _indexPathsForHighlightedItems@32, _reloadingSuspendedCount@36, _firstResponderView@40, _newContentView@44, _firstResponderViewType@48, … (+28) |
| UICollectionViewCell | UICollectionReusableView | 50 | _contentView@20, _backgroundView@24, _selectedBackgroundView@28, _menuGesture@32, _selectionSegueTemplate@36, _highlightingSupport@40, _collectionCellFlags@44, _selected@48, _highlighted@49 |
| UICollectionViewController | UIViewController | 16 | _clearsSelectionOnViewWillAppear@4, _useLayoutToLayoutNavigationTransitions@5, _collectionView@8, _layout@12 |
| UICollectionViewData | - | 56 | _validLayoutRect@4, _numItems@20, _numSections@24, _sectionItemCounts@28, _contentSize@32, _collectionViewDataFlags@40, _collectionView@44, _layout@48, _cachedLayoutAttributes@52 |
| UICollectionViewExt | - | 28 | _collectionViewDelegate@4, _nibLayout@8, _nibCellsExternalObjects@12, _supplementaryViewsExternalObjects@16, _touchingIndexPath@20, _currentIndexPath@24 |
| UICollectionViewFlowLayout | UICollectionViewLayout | 120 | _gridLayoutFlags@4, _interitemSpacing@8, _lineSpacing@12, _itemSize@16, _headerReferenceSize@24, _footerReferenceSize@32, _sectionInset@40, _data@56, _currentLayoutSize@60, _insertedItemsAttributesDict@68, _insertedSectionHeadersAttributesDict@72, _insertedSectionFootersAttributesDict@76, … (+7) |
| UICollectionViewLayout | - | 44 | _collectionView@4, _collectionViewBoundsSize@8, _initialAnimationLayoutAttributesDict@16, _finalAnimationLayoutAttributesDict@20, _deletedSectionsSet@24, _insertedSectionsSet@28, _decorationViewClassDict@32, _decorationViewNibDict@36, _decorationViewExternalObjectsTables@40 |
| UICollectionViewLayoutAttributes | - | 128 | _reuseIdentifier@4, _layoutFlags@8, _hidden@12, _elementKind@16, _alpha@20, _zIndex@24, _indexPath@28, _center@32, _size@40, _frame@48, _transform@64 |
| UICollectionViewUpdateItem | - | 20 | _initialIndexPath@4, _finalIndexPath@8, _updateAction@12, _gap@16 |
| UIColor | - | 12 | _CGColor@4, _CIColor@8 |
| UIControl | UIView | 28 | _targetActions@4, _previousPoint@8, _downTime@16, _controlFlags@24 |
| UIControlAction | - | 16 | _target@4, _action@8, _controlEvents@12 |
| UIDatePicker | UIControl | 48 | _pickerView@4, _datePickerMode@8, _locale@12, _calendar@16, _timeZone@20, _date@24, _minimumDate@28, _maximumDate@32, _minuteInterval@36, _countDownDuration@40 |
| UIDevice | - | 24 | _supportedOrientations@4, _generatesDeviceOrientationNotifications@5, _batteryMonitoringEnabled@6, _proximityMonitoringEnabled@7, _proximityState@8, _orientation@12, _batteryState@16, _batteryLevel@20 |
| UIDocument | - | 28 | _fileURL@4, _localizedName@8, _fileType@12, _fileModificationDate@16, _documentState@20, _undoManager@24 |
| UIDocumentInteractionController | - | 32 | _delegate@4, _URL@8, _UTI@12, _name@16, _icons@20, _annotation@24, _gestureRecognizers@28 |
| UIEvent | - | 8 | _eventId@4 |
| UIFont | - | 8 | _CTFont@4 |
| UIFontCache | - | 12 | _cache@4, _prototypeCache@8 |
| UIFontCacheSimpleKey | - | 16 | _name@4, _size@8, _traits@12 |
| UIFontDescriptor | - | 8 | _fontAttributes@4 |
| UIGestureRecognizer | - | 36 | _targets@4, _lastEvent@8, _internalCount@12, _touchEventId@16, _enabled@20, _cancelsTouchesInView@21, _delaysTouchesBegan@22, _delaysTouchesEnded@23, _delegate@24, _state@28, _view@32 |
| UIGestureRecognizerTargetActionPair | - | 12 | _target@4, _action@8 |
| UIGridLayoutInfo | - | 52 | _sections@4, _visibleBounds@8, _layoutSize@24, _isValid@32, _usesFloatingHeaderFooter@33, _horizontal@34, _leftToRight@35, _rowAlignmentOptions@36, _dimension@40, _contentSize@44 |
| UIGridLayoutItem | - | 28 | _section@4, _rowObject@8, _itemFrame@12 |
| UIGridLayoutRow | - | 60 | _items@4, _isValid@8, _verticalAlignement@12, _horizontalAlignement@16, _complete@20, _fixedItemSize@21, _section@24, _index@28, _itemCount@32, _rowSize@36, _rowFrame@44 |
| UIGridLayoutSection | - | 152 | _items@4, _rows@8, _isValid@12, _fixedItemSize@13, _lastRowIncomplete@14, _itemsCount@16, _verticalInterstice@20, _horizontalInterstice@24, _headerDimension@28, _footerDimension@32, _layoutInfo@36, _rowAlignmentOptions@40, … (+14) |
| UIImage | - | 72 | _imageFlags@4, _imageRef@8, _scale@12, _CIImage@16, _images@20, _resizingMode@24, _renderingMode@28, _duration@32, _capInsets@40, _alignmentRectInsets@56 |
| UIImageNibPlaceholder | UIImage | 8 | runtimeResourceName@4 |
| UIImagePickerController | UINavigationController | 80 | visible@4, targetURL@8, _showsCameraControls@12, _allowsEditing@13, _allowsImageEditing@14, _sourceType@16, _mediaTypes@20, _delegate@24, _videoQuality@28, _cameraOverlayView@32, _cameraCaptureMode@36, _cameraDevice@40, … (+3) |
| UIImageView | UIView | 56 | _image@4, _highlighted@8, _isHighlighted@12, _currentAnimationImageIndex@16, _currentAnimationRepeats@20, _animationImages@24, _animationTimer@28, _highlightedAnimationImages@32, _animationRepeatCount@36, _tintColor@40, _animationDuration@48 |
| UILabel | UIView | 84 | _size@4, _text@12, _minimumScaleFactor@16, _color@20, _highlightedColor@24, _shadowColor@28, _font@32, _shadowOffset@36, _minFontSize@44, _numberOfLines@48, _lastLineBaseline@52, _lineSpacing@56, … (+5) |
| UILocalNotification | - | 20 | _proxy@4, _fired@8, _unscheduled@9, _repeatInterval@12, _repeatCalendar@16 |
| UILocalizedIndexedCollation | - | 12 | _sectionTitles@4, _sectionIndexTitles@8 |
| UILongPressGestureRecognizer | UIGestureRecognizer | 48 | _touchLocation@4, _touchTime@16, _timer@24, _allowableMovement@28, _numberOfTapsRequired@32, _numberOfTouchesRequired@36, _minimumPressDuration@40 |
| UIManager | - | 155 | world@4, dynamicWorld@8, cache@12, windowInfo@16, worldUI@20, pauseUI@24, mapUI@28, tcUI@32, dpad@36, tcUIDisplayed@40, workbenchChoiceUI@44, craftUI@48, … (+34) |
| UIMenuController | - | 48 | _targetRect@4, _arrowDirection@20, _menuVisible@24, _menuItems@28, _menuFrame@32 |
| UINamedImage | UIImage | 88 | _path@72, _size@76, _image@84 |
| UINavigationBar | UIView | 44 | _barStyle@4, _items@8, _tintColor@12, _delegate@16, _translucent@20, _barTintColor@24, _shadowImage@28, _titleTextAttributes@32, _backIndicatorImage@36, _backIndicatorTransitionMaskImage@40 |
| UINavigationContainer | UIView | 20 | navigationController@4, navigationBar@8, view@12, toolbar@16 |
| UINavigationController | UIViewController | 44 | _container@4, _visibleController@8, _navigationBar@12, _toolbar@16, _builtinTransitionGap@20, _builtinTransitionStyle@24, _navigationControllerFlags@28, _navigationBarHidden@32, _delegate@36, _interactivePopGestureRecognizer@40 |
| UINavigationItem | - | 44 | _title@4, _leftBarButtonItems@8, _rightBarButtonItems@12, _navigationBar@16, _leftItemsSupplementBackButton@20, _hidesBackButton@21, _leftBarButtonItem@24, _rightBarButtonItem@28, _backBarButtonItem@32, _titleView@36, _prompt@40 |
| UINib | - | 8 | storage@4 |
| UINibDecoder | - | 792 | arrayClass@4, setClass@8, dictionaryClass@12, classes@16, missingClasses@20, objects@24, values@28, valueTypes@32, valueData@36, valueDataSize@40, header@44, objectsByObjectID@96, … (+13) |
| UINibKeyValuePair | - | 16 | object@4, keyPath@8, value@12 |
| UINibStorage | - | 30 | bundleResourceName@4, bundleDirectoryName@8, bundle@12, identifierForStringsFile@16, archiveData@20, nibDecoder@24, instantiatingForSimulator@28, captureImplicitLoadingContextOnDecode@29 |
| UINibStringIDTable | - | 20 | table@4, buckets@8, hashMask@12, count@16 |
| UIPageControl | UIControl | 28 | _indicators@4, _currentPage@8, _displayedPage@12, _pageControlFlags@16, _pageIndicatorTintColor@20, _currentPageIndicatorTintColor@24 |
| UIPageViewController | UIViewController | 36 | _doubleSided@4, _delegate@8, _dataSource@12, _transitionStyle@16, _navigationOrientation@20, _spineLocation@24, _gestureRecognizers@28, _viewControllers@32 |
| UIPanGestureRecognizer | UIGestureRecognizer | 76 | _minimumNumberOfTouches@4, _maximumNumberOfTouches@8, _touches@12, _lastCenterPoint@16, _lastTimestamp@24, _centerPoint@32, _timestamp@40, _translating@48, _translation@52, _velocity@60, _panPoint@68 |
| UIPasteboard | - | 20 | _name@4, _items@8, _persistent@12, _changeCount@16 |
| UIPickerView | UIView | 24 | _rowHeight@4, showsSelectionIndicator@8, _numberOfComponents@12, _dataSource@16, _delegate@20 |
| UIPinchGestureRecognizer | UIGestureRecognizer | 60 | firstTouch@4, secondTouch@8, firstTouchStartLocation@12, secondTouchStartLocation@20, _lastDistance@28, _lastTimeSampled@32, _startScale@40, _startDistance@44, _trackingPinch@48, _shouldBeginNext@49, _scale@52, _velocity@56 |
| UIPopoverController | - | 48 | _popoverVisible@4, delegate@8, _contentViewController@12, _passthroughViews@16, _popoverBackgroundViewClass@20, _popoverContentSize@24, _popoverLayoutMargins@32 |
| UIProgressView | UIView | 32 | _progress@4, _trackView@8, _progressView@12, _isAnimating@16, _progressViewStyle@20, _progressTintColor@24, _trackTintColor@28 |
| UIProxyObject | - | 8 | proxiedObjectIdentifier@4 |
| UIRefreshControl | UIControl | 16 | _refreshing@4, _tintColor@8, _attributedTitle@12 |
| UIResponder | - | 8 | _nextResponder@4 |
| UIRotationGestureRecognizer | UIGestureRecognizer | 56 | rotation@4, velocity@8, prevDeltaToAdd@12, prevRotationDelta@16, firstTouch@20, secondTouch@24, firstTouchLastLocation@28, secondTouchLastLocation@36, initialTime@48 |
| UIRoundedRectButton | UIButton | 20 | _fillPath@4, _fillColor@8, _tableViewStyleBackground@12, _shadowView@16 |
| UIRuntimeAccessibilityConfiguration | - | 24 | accessibilityConfigurationHint@4, accessibilityConfigurationLabel@8, accessibilityConfigurationTraits@12, isAccessibilityConfigurationElement@16, object@20 |
| UIRuntimeConnection | - | 16 | source@4, destination@8, label@12 |
| UIRuntimeEventConnection | UIRuntimeConnection | 20 | eventMask@16 |
| UIRuntimeOutletCollectionConnection | UIRuntimeConnection | 21 | runtimeCollectionClassName@16, addsContentToExistingCollection@20 |
| UIScreen | - | 28 | _currentMode@4, _wantsSoftwareDimming@8, availableModes@12, _overscanCompensation@16, _mirroredScreen@20, _brightness@24 |
| UIScreenMode | - | 16 | _scale@4, _size@8 |
| UIScrollView | UIView | 96 | _scrollViewFlags@4, _tracking@8, _zooming@9, _zoomBouncing@10, _delegate@12, _indicatorStyle@16, _decelerationRate@20, _minimumZoomScale@24, _maximumZoomScale@28, _zoomScale@32, _panGestureRecognizer@36, _pinchGestureRecognizer@40, … (+5) |
| UISearchBar | UIView | 160 | _barStyle@4, _delegate@8, _text@12, _prompt@16, _placeholder@20, _showsBookmarkButton@24, _showsCancelButton@25, _showsSearchResultsButton@26, _searchResultsButtonSelected@27, _tintColor@28, _translucent@32, _autocapitalizationType@36, … (+24) |
| UISearchDisplayController | - | 100 | _viewController@4, _tableView@8, _dimmingView@12, _searchBar@16, _noResultsLabel@20, _noResultsMessage@24, _resultsTitle@28, _delegate@32, _tableViewDataSource@36, _tableViewDelegate@40, _containingScrollViews@44, _lastKeyboardAdjustment@48, … (+13) |
| UISegment | UIImageView | 12 | _title@4, _position@8 |
| UISegmentedControl | UIControl | 60 | _segments@4, _selectedSegment@8, _highlightedSegment@12, _removedSegment@16, _delegate@20, _tintColor@24, _barStyle@28, _appearanceStorage@32, _backgroundBarView@36, _enabledAlpha@40, _segmentedControlFlags@44, _momentary@48, … (+3) |
| UIShakeEvent | UIEvent | 16 | _timestamp@8 |
| UISlider | UIControl | 76 | _value@4, _minValue@8, _maxValue@12, _contentLookup@16, _minValueImageView@20, _maxValueImageView@24, _thumbView@28, _minTrackView@32, _maxTrackView@36, _sliderFlags@40, _hitOffset@44, _minTintColor@48, … (+6) |
| UISliderImageView | UIImageView | 8 | _slider@4 |
| UISplitViewController | UIViewController | 16 | _presentsWithGesture@4, _viewControllers@8, _delegate@12 |
| UIStepper | UIControl | 72 | _isRtoL@4, _middleView@8, _plusButton@12, _minusButton@16, _repeatTimer@20, _repeatCount@24, _continuous@28, _autorepeat@29, _wraps@30, _tintColor@32, _value@40, _minimumValue@48, … (+2) |
| UIStoryboard | - | 24 | bundle@4, storyboardFileName@8, identifierToNibNameMap@12, designatedEntryPointIdentifier@16, identifierToUINibMap@20 |
| UIStoryboardEmbedSegue | UIStoryboardSegue | 12 | _containerView@4, containerView@8 |
| UIStoryboardEmbedSegueTemplate | UIStoryboardSegueTemplate | 28 | _containerView@24 |
| UIStoryboardModalSegueTemplate | UIStoryboardSegueTemplate | 33 | _useDefaultModalPresentationStyle@21, _useDefaultModalTransitionStyle@22, _modalPresentationStyle@24, _modalTransitionStyle@28, _animates@32 |
| UIStoryboardPopoverSegue | UIStoryboardSegue | 40 | _popoverController@4, _passthroughViews@8, _permittedArrowDirections@12, _anchorView@16, _anchorBarButtonItem@20, _anchorRect@24 |
| UIStoryboardPopoverSegueTemplate | UIStoryboardSegueTemplate | 40 | _permittedArrowDirections@24, _passthroughViews@28, _anchorBarButtonItem@32, _anchorView@36 |
| UIStoryboardPushSegue | UIStoryboardSegue | 12 | _destinationContainmentContext@4, _splitViewControllerIndex@8 |
| UIStoryboardPushSegueTemplate | UIStoryboardSegueTemplate | 32 | _destinationContainmentContext@24, _splitViewControllerIndex@28 |
| UIStoryboardReplaceSegue | UIStoryboardSegue | 12 | _destinationContainmentContext@4, _splitViewControllerIndex@8 |
| UIStoryboardReplaceSegueTemplate | UIStoryboardSegueTemplate | 32 | _destinationContainmentContext@24, _splitViewControllerIndex@28 |
| UIStoryboardScene | - | 8 | sceneViewController@4 |
| UIStoryboardSegue | - | 20 | _identifier@4, _sourceViewController@8, _destinationViewController@12, _performHandler@16 |
| UIStoryboardSegueTemplate | - | 21 | _identifier@4, _segueClassName@8, _viewController@12, _destinationViewControllerIdentifier@16, _performOnViewLoad@20 |
| UIStretchableImage | UIImage | 88 | _edgeInsets@72 |
| UISwipeGestureRecognizer | UIGestureRecognizer | 20 | _numberOfTouchesRequired@4, _direction@8, _numberOfTouches@12, _startingTouches@16 |
| UISwitch | UIControl | 28 | _onTintColor@4, _on@8, _tintColor@12, _thumbTintColor@16, _onImage@20, _offImage@24 |
| UITabBar | UIView | 60 | _translucent@4, items@8, selectedItem@12, delegate@16, _tintColor@20, _barTintColor@24, _selectedImageTintColor@28, _backgroundImage@32, _selectionIndicatorImage@36, _shadowImage@40, _itemPositioning@44, _itemWidth@48, … (+2) |
| UITabBarController | UIViewController | 36 | _container@4, viewControllers@8, tabBar@12, selectedIndex@16, customizableViewControllers@20, selectedViewController@24, delegate@28, moreNavigationController@32 |
| UITabBarItem | UIBarItem | 12 | badgeValue@4, _selectedImage@8 |
| UITableView | UIScrollView | 104 | _disableVirtualization@4, _numberOfSections@8, _tableFlags@12, _delegateFlags@16, _dataSourceFlags@20, _sectionIndexMinimumDisplayRowCount@24, _rowHeight@28, _sectionHeaderHeight@32, _sectionFooterHeight@36, _backgroundView@40, _tableHeaderView@44, _tableFooterView@48, … (+13) |
| UITableViewCell | UIView | 80 | _selected@4, _highlighted@5, _showingDeleteConfirmation@6, _showsReorderControl@7, _shouldIndentWhileEditing@8, _editing@9, _eligibleForTap@10, _contentView@12, _backgroundView@16, _textLabel@20, _imageView@24, _reuseIdentifier@28, … (+12) |
| UITableViewCellContentView | UIView | 8 | _mask@4 |
| UITableViewController | UIViewController | 20 | _clearsSelectionOnViewWillAppear@4, _style@8, _staticDataSource@12, _refreshControl@16 |
| UITapGestureRecognizer | UIGestureRecognizer | 24 | _touchLocation@4, _touches@12, _numberOfTapsRequired@16, _numberOfTouchesRequired@20 |
| UITextField | UIControl | 116 | _text@4, _textColor@8, _font@12, _originalFontSize@16, _placeholder@20, _inputTraits@24, _editingLength@28, _observers@32, _textFieldFlags@36, _clearsOnBeginEditing@40, _adjustsFontSizeToFitWidth@41, _editing@42, … (+19) |
| UITextInputMode | - | 8 | _primaryLangauge@4 |
| UITextRange | - | 16 | _empty@4, _start@8, _end@12 |
| UITextView | UIScrollView | 100 | _text@4, _editingLength@8, _font@12, _color@16, _selectedRange@20, _inputTraits@28, _editable@32, _selectable@33, _allowsEditingTextAttributes@34, _clearsOnInsertion@35, selectedTextRange@36, markedTextRange@40, … (+14) |
| UIToolbar | UIView | 28 | _items@4, _style@8, _tint@12, _translucent@16, _barTintColor@20, _delegate@24 |
| UITouch | - | 56 | _phase@4, _timestamp@8, _previousLocation@16, _locationInWindow@24, _tapCount@32, _view@36, _gestureRecognizers@40, _hasMoved@44, _lastUp@48 |
| UITouchEvent | UIEvent | 68 | _touchPool@4, _allTouches@44, _timestamp@48, _lastPhase@56, _lastIndex@60, _taps@64 |
| UIView | UIResponder | 144 | _bounds@4, _frame@20, _transform@36, _superview@60, _barMetricsOffset@64, _layer@68, _subviews@72, __backgroundColor@76, _gestureRecognizers@80, _alpha@84, _contentMode@88, _contentStretch@92, … (+9) |
| UIViewContext | - | 16 | _view@4, _uiContext@8, _lockedBackgroundBitmap@12 |
| UIViewController | UIResponder | 140 | _view@4, _navigationItem@8, _nibName@12, _rootItems@16, _hidesBottomBarWhenPushed@20, _title@24, _tabBarItem@28, _tabBarController@32, _childViewControllers@36, _window@40, _interfaceOrientation@44, _storyboardSegueTemplates@48, … (+22) |
| UIWebView | UIView | 48 | _client@4, _webViewFlags@8, _suppressesIncrementalRendering@12, _keyboardDisplayRequiresUserAction@13, _delegate@16, _scrollView@20, _request@24, _paginationMode@28, _paginationBreakingMode@32, _pageLength@36, _gapBetweenPages@40, _pageCount@44 |
| UIWebViewController | UIViewController | 16 | _webView@4, _prefixes@8, _completionBlock@12 |
| UIWindow | UIView | 16 | _rootViewController@4, _screen@8, _windowLevel@12 |
| VerdeActivity | - | 76 | _delegate@72 |
| VerdePluginAlertDelegate | - | 12 | callbackArg@4, callback@8 |
| VinePlant | Plant | 184 | availableFood@100, checkWeatherCount@104, killCount@108, belowGatherProgress@112, growthTimer@176, numberOfOccupiedTilesBelow@180 |
| WHThreadSafeQueue | - | 12 | lock@4, queue@8 |
| WearUI | GameUIView | 160 | world@20, blockhead@24, frameSize@28, backgroundShader@36, backgroundTexture@40, itemsTexture@44, type@48, putOnTakeOffTextView@52, clothingImage@56, wearButton@60, longWorkBenchTitle@64, longWorkBenchDescription@68, … (+6) |
| Weather | - | 664 | cache@4, world@8, snowPoints@12, rainPoints@16, cloudPoints@20, cloudQuadCount@24, clouds@28, cloudTextures@412, cloudNoiseFunction@436, cloudsLoadedAsHD@440, timeElapsed@444, timeElapsedCloud@448, … (+31) |
| Window | DynamicObject | 60 | itemType@56 |
| Wire | DynamicObject | 68 | itemType@56, currentConfiguration@60, currentSolidConfiguration@64 |
| WirePathCreator | - | 40 | world@4, openList@8, closedList@12, startIndex@16, derivedTilePropertiesArray@20, derivedTileCount@24, derivedTileIndices@28 |
| Workbench | InteractionObject | 324 | light@100, worldObjectShader@104, currentFuelBlockhead@108, isInUseFuel@112, savedBlockheadIndexFuel@116, type@120, numberOfCraftableItems@124, numberOfCraftableItemsUpToCurrentLevel@128, craftableItems@132, selectedIndex@136, sourceItems@140, xScroll@172, … (+36) |
| WorkbenchChoiceUI | GameUIView | 164 | world@20, backgroundShader@24, backgroundTexture@28, orthoMatrix@32, windowInfo@96, cache@100, dynamicObject@104, blockhead@108, craftButton@112, craftOptionBButton@116, craftOptionCButton@120, addFuelButton@124, … (+13) |
| WorkbenchProgressBarUI | GameUIView | 128 | world@20, backgroundShader@24, backgroundTexture@28, orthoMatrix@32, windowInfo@96, cache@100, workbench@104, titleTextView@108, energyTextView@112, progressShader@116, translationOffset@120 |
| World | - | 3464 | motionManager@4, interfaceOrientation@8, worldWidthMacro@12, supportsGyro@16, isObservingMotionEvents@17, motionUpdateTimer@20, calibrating@24, hasCalibrated@25, longTermAveragedAcceleration@28, calibrationMatrix@44, dragInProgress@108, forcedCalibrationTimer@112, … (+230) |
| WorldTileLoader | - | 260 | world@4, randomSeed@8, blockDirectory@12, heightNoiseFunctionA@16, heightNoiseFunctionB@20, faultNoiseFunction@24, treeDensityNoiseFunction@28, rockTypeNoiseFunction@32, flintDensityNoiseFunction@36, tinDensityNoiseFunction@40, sandNoiseFunction@44, seasonOffsetNoiseFunction@48, … (+20) |
| WorldUI | - | 300 | world@4, uiManager@8, itemsTexture@12, currentBlockhead@16, client@20, server@24, touchIndex@28, multiplayerButton@32, netPlayerButtons@36, netPlayerButtonsActiveTimer@40, netPlayerButtonsAnimationTimer@44, orthoMatrix@48, … (+49) |
| Yak | DonkeyLike | 1144 | hornTexture@840, bodyTextureShaved@844, bodyTextureHairy@848, legsTextureShaved@852, legsTextureHairy@856, bodyCubeHairy@860, bodyCubeShaved@864, hornCubeA@868, hornCubeB@872, leftHornMatrixA@880, rightHornMatrixA@944, leftHornMatrixB@1008, … (+3) |
| _UICollectionViewItemKey | - | 20 | _isClone@4, _type@8, _indexPath@12, _identifier@16 |
| _UIKeyInputHelper | - | 12 | keyInputProtocolImplementation@4, textField@8 |
| _UISegment | UIImageView | 24 | _width@4, _enabled@8, _contentOffset@12, _label@20 |
| _UITabBarControllerContainer | UIView | 8 | _viewControllerViewContainer@4 |
| _UITableViewCellSeparatorView | UIView | 16 | _drawsWithVibrantLightMode@4, _backgroundView@8, _overlayView@12 |
| _UITableViewClassCellProvider | - | 12 | _reuseIdentifier@4, _cellClass@8 |
| _UITableViewNibCellProvider | - | 12 | _reuseIdentifier@4, _nib@8 |
| _UITableViewRow | - | 24 | _indexPath@4, _frame@8 |
| _UITableViewSection | - | 32 | _headerRow@4, _footerRow@8, _cellRows@12, _frame@16 |
| _UITextInputTraits | - | 36 | enablesReturnKeyAutomatically@4, autocapitalizationType@8, secureTextEntry@12, autocorrectionType@16, spellCheckingType@20, keyboardAppearance@24, returnKeyType@28, keyboardType@32 |
| _WebDialog | - | 20 | _delegate@16 |
