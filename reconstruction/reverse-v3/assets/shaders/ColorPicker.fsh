//
//  Shader.fsh
//  SandLandiPad
//
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
//

//varying lowp vec4 colorVarying;

uniform highp float brightness;

varying highp vec2 outPickerCoord;

void main()
{
    highp vec4 pickerColor = vec4(0.0,0.0,0.0,1.0);
    
    highp float oneSixth = 1.0 / 6.0;
    highp float oneThird = 1.0 / 3.0;
    
    pickerColor.r = clamp(1.0 - (outPickerCoord.x - oneSixth) / oneSixth, 0.0, 1.0);
    pickerColor.r += clamp((outPickerCoord.x - oneSixth * 4.0) / oneSixth, 0.0, 1.0);
    
    pickerColor.g = clamp(1.0 - ((abs(outPickerCoord.x - oneThird) - oneSixth) / oneSixth), 0.0, 1.0);
    pickerColor.b = clamp(1.0 - ((abs(outPickerCoord.x - oneThird * 2.0) - oneSixth) / oneSixth), 0.0, 1.0);
    
    pickerColor = mix(pickerColor, vec4(1.0,1.0,1.0,1.0), outPickerCoord.y) * vec4(brightness,brightness,brightness,1.0);
    
    highp float whiteBorder = step(1.0, outPickerCoord.y);
    whiteBorder += step(1.0, outPickerCoord.x);
    whiteBorder += step(1.0, 1.0 - outPickerCoord.y);
    whiteBorder += step(1.0, 1.0 - outPickerCoord.x);
        
    gl_FragColor = mix(pickerColor, vec4(1.0,1.0,1.0,1.0), whiteBorder);
}
