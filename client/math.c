//
// Created by unnamedfurry on 8/28/26.
//

float clamp(float val, float min, float max) {
    if (val < min) return min;
    if (val > max) return max;
    return val;
}