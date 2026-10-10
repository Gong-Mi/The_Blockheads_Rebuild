# World closure sweep part 2 (E115)

The World accessor tail that closes the class. 72 bodies, 1204 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| wy_00 | World -[pinchScale] | 0x005da2d8 | 25 | 0 | 0 | 1 | 0 | 1 | 0 |
| wy_01 | World -[stopFollowingOrTranslatingToGoal] | 0x005bde3c | 24 | 0 | 0 | 2 | 0 | 0 | 0 |
| wy_02 | World -[dayColor] | 0x005d9b88 | 24 | 0 | 0 | 1 | 0 | 1 | 0 |
| wy_03 | World -[startPortalPos] | 0x005d9d24 | 24 | 0 | 0 | 1 | 0 | 1 | 0 |
| wy_04 | World -[roundedTranslation] | 0x005da3e4 | 24 | 0 | 0 | 1 | 0 | 1 | 0 |
| wy_05 | World -[windStrength] | 0x005d7970 | 22 | 1 | 0 | 1 | 0 | 1 | 0 |
| wy_06 | World -[tutorialActive] | 0x005cedac | 21 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_07 | World -[dieConfirmationConfirmed:] | 0x005cee6c | 20 | 1 | 1 | 0 | 0 | 1 | 0 |
| wy_08 | World -[customRules] | 0x005d5584 | 19 | 0 | 0 | 1 | 0 | 1 | 0 |
| wy_09 | World -[highestPoint] | 0x005c6eb0 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_10 | World -[weatherFraction] | 0x005d9ab0 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_11 | World -[rainFraction] | 0x005d9af8 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_12 | World -[rainFractionNotIncludingSnow] | 0x005d9b40 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_13 | World -[macroTiles] | 0x005d989c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_14 | World -[dynamicWorld] | 0x005d98e0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_15 | World -[saveID] | 0x005d9924 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_16 | World -[setTranslatingToGoal:] | 0x005d9c24 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_17 | World -[windowInfo] | 0x005d9ce0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_18 | World -[serverClients] | 0x005d9d84 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_19 | World -[server] | 0x005d9dc8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_20 | World -[client] | 0x005d9e0c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_21 | World -[worldName] | 0x005d9ec8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_22 | World -[setIsAdmin:] | 0x005d9f48 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_23 | World -[setIsMod:] | 0x005d9fc8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_24 | World -[setIsOwner:] | 0x005da048 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_25 | World -[setCloudMode:] | 0x005da0c8 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_26 | World -[portalChestManager] | 0x005da1d0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_27 | World -[setFollowingBlockhead:] | 0x005da250 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_28 | World -[tutorial] | 0x005da294 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_29 | World -[cloudInterface] | 0x005da480 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_30 | World -[setCloudInterface:] | 0x005da4c4 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_31 | World -[setSaveDisabled:] | 0x005da544 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_32 | World -[uiManager] | 0x005da63c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_33 | World -[foundItemsList] | 0x005da680 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_34 | World -[doPortalShotNextFrame] | 0x005d8e90 | 16 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_35 | World -[delegate] | 0x005da6c4 | 16 | 0 | 0 | 0 | 0 | 0 | 0 |
| wy_36 | World -[setDelegate:] | 0x005da704 | 16 | 0 | 0 | 0 | 0 | 0 | 0 |
| wy_37 | World -[distanceOrderedFoodTypes] | 0x005bdd70 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_38 | World -[welcomeMessage] | 0x005cfa4c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_39 | World -[serverPassword] | 0x005d1724 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_40 | World -[clientPassword] | 0x005d1760 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_41 | World -[serverPrivacySetting] | 0x005d1a68 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_42 | World -[customRulesDict] | 0x005d55d0 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_43 | World -[dpadControl] | 0x005d7b60 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_44 | World -[dpadDirectControlDisabled] | 0x005d7cac | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_45 | World -[hasFinishedDatabaseMigrationTo17] | 0x005d8ed0 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_46 | World -[expertMode] | 0x005d9860 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_47 | World -[randomSeed] | 0x005d9968 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_48 | World -[isAdmin] | 0x005d9f0c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_49 | World -[isMod] | 0x005d9f8c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_50 | World -[isOwner] | 0x005da00c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_51 | World -[cloudMode] | 0x005da08c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_52 | World -[serverMinorVersion] | 0x005da194 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_53 | World -[followingBlockhead] | 0x005da214 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_54 | World -[dragInProgress] | 0x005da3a8 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_55 | World -[saveDisabled] | 0x005da508 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_56 | World -[slowAnimationIndex] | 0x005da588 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_57 | World -[waterAnimationIndex] | 0x005da5c4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wy_58 | World -[workbenchChoiceUIDisplayed] | 0x005da744 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| wy_59 | World -[newBlockheadUIDisplayed] | 0x005da780 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| wy_60 | World -[paintMixUIDisplayed] | 0x005da7bc | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| wy_61 | World -[addFuelUIDisplayed] | 0x005da7f8 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| wy_62 | World -[jetPackUIDisplayed] | 0x005da834 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| wy_63 | World -[sleepProgressUIDisplayed] | 0x005da870 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| wy_64 | World -[regenerateUIDisplayed] | 0x005da8ac | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| wy_65 | World -[hungerUIDisplayed] | 0x005da8e8 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| wy_66 | World -[wearUIDisplayed] | 0x005da924 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| wy_67 | World -[popUpUIDisplayed] | 0x005da960 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| wy_68 | World -[tradingPostSellUIDisplayed] | 0x005da99c | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| wy_69 | World -[tradingPostBuyUIDisplayed] | 0x005da9d8 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| wy_70 | World -[workbenchProgressBarUIDisplayed] | 0x005daa50 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| wy_71 | World -[usedPhysicalBlocks] | 0x005d8e58 | 14 | 0 | 0 | 1 | 0 | 0 | 0 |

## What this sweep closes

The World accessor tail - 72 bodies, 1204 words, seven call rows in the
whole batch:

- The struct copiers: pinchScale (25w), dayColor (24w), startPortalPos (24w),
  roundedTranslation (24w) - objc_copyStruct 8-byte returns - and customRules
  (19w, memcpy).
- The delegate/weather reads: windStrength (22w, [weather windStrength]).
- The state writers: stopFollowingOrTranslatingToGoal (24w),
  dieConfirmationConfirmed: (20w), setTranslatingToGoal:/setFollowingBlockhead:
  /setIsAdmin:/setIsMod:/setIsOwner:/setCloudMode:/setCloudInterface:/
  setSaveDisabled: setter family.
- The boolean -UIDisplayed flag bank (13 bodies: workbenchChoiceUI,
  newBlockheadUI, paintMixUI, addFuelUI, jetPackUI, sleepProgressUI,
  regenerateUI, hungerUI, wearUI, popUpUI, tradingPostSellUI, tradingPostBuyUI,
  workbenchProgressBarUI): ldrsb byte reads at compile-time offsets whose slot
  cells are not dynsym-named as World ivars - recorded as-is.
- The remaining plain getters (macroTiles, dynamicWorld, serverClients, server,
  client, worldName, uiManager, saveID, windowInfo, welcomeMessage,
  serverPassword/clientPassword, privacy/minor-version, randomSeed, drag/
  animation indices, foundItemsList, tutorial, cloud bits, weather fractions,
  highestPoint, usedPhysicalBlocks ...).

With this sweep the World instance-method set has no refs=False bodies left
outside the loadPhysical/init cores already collected in E104-E114.
