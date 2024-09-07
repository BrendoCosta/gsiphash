// SPDX-License-Identifier: MIT

import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/iterator
import gleam/result

const message_block_length = 8 // bytes = 64-bit integers

/// This function is need as Erlang uses arbitrary size integers
/// and the algorithm requires 64-bit integer operations. It will
/// drops out anything after the 8th byte (mask it to 64-bit integer).
fn i64_cast(value: Int) -> Int
{
    int.bitwise_and(value, 0xffffffffffffffff)
}

fn i64_get(data: BitArray) -> Result(Int, String)
{
    case bit_array.slice(at: 0, from: <<data:bits, 0x00:size(64)>>, take: 8)
    {
        Ok(<<value:unsigned-little-size(64)>>) -> Ok(value)
        _ -> Error("gsiphash.i64_get: couldn't get integer from data")
    }
}

fn rotate_left(value: Int, bits: Int) -> Int
{
    int.bitwise_or(i64_cast(int.bitwise_shift_left(value, bits)), i64_cast(int.bitwise_shift_right(value, message_block_length * 8 - bits)))
}

fn sip_round(v0: Int, v1: Int, v2: Int, v3: Int) -> #(Int, Int, Int, Int)
{
    let v0 = i64_cast(v0 + v1)
    let v1 = rotate_left(v1, 13)
    let v1 = int.bitwise_exclusive_or(v1, v0)
    let v0 = rotate_left(v0, 32)

    let v2 = i64_cast(v2 + v3)
    let v3 = rotate_left(v3, 16)
    let v3 = int.bitwise_exclusive_or(v3, v2)

    let v2 = i64_cast(v2 + v1)
    let v1 = rotate_left(v1, 17)
    let v1 = int.bitwise_exclusive_or(v1, v2)
    let v2 = rotate_left(v2, 32)

    let v0 = i64_cast(v0 + v3)
    let v3 = rotate_left(v3, 21)
    let v3 = int.bitwise_exclusive_or(v3, v0)

    #(v0, v1, v2, v3)
}

pub fn siphash_2_4(from data: BitArray, using key: BitArray)
{
    siphash(from: data, using: key, with_c_rounds: 2, with_d_rounds: 4)
}

pub fn siphash(from data: BitArray, using key: BitArray, with_c_rounds c: Int, with_d_rounds d: Int) -> Result(Int, String)
{
    //let data = <<0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e>>
    //let key = <<0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f>>
    //let c = 2
    //let d = 4

    let data_length = bit_array.byte_size(data)

    use <- bool.guard(when: c <= 0, return: Error("gsiphash.siphash: the count of C rounds must be greater than zero"))
    use <- bool.guard(when: d <= 0, return: Error("gsiphash.siphash: the count of D rounds must be greater than zero"))
    use <- bool.guard(when: bit_array.byte_size(key) != 16, return: Error("gsiphash.siphash: the length of the key must be 16 bytes (128 bits)"))

    // Since we need to process the data in "words" (blocks/chunks) of
    // 8 bytes each, there will be bytes left out when the length of
    // the data is not divisible by 8.
    let left_out_bytes_count = data_length % message_block_length // inlen & 7 in reference C code
    
    // Initialization
    
    use k0 <- result.try(
        {
            use slice <- result.try(result.replace_error(bit_array.slice(at: 0, from: key, take: 8), "gsiphash.siphash: couldn't get the MSB slice of the key"))
            i64_get(slice)
        }
    )
    use k1 <- result.try(
        {
            use slice <- result.try(result.replace_error(bit_array.slice(at: 8, from: key, take: 8), "gsiphash.siphash: couldn't get the LSB slice of the key"))
            i64_get(slice)
        }
    )

    //let assert <<0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00>> = <<k0:size(64)>>
    //let assert <<0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08>> = <<k1:size(64)>>

    let v0 = int.bitwise_exclusive_or(k0, 0x736f6d6570736575)
    let v1 = int.bitwise_exclusive_or(k1, 0x646f72616e646f6d)
    let v2 = int.bitwise_exclusive_or(k0, 0x6c7967656e657261)
    let v3 = int.bitwise_exclusive_or(k1, 0x7465646279746573)

    //let assert 0x7469686173716475 = v0
    //let assert 0x6b617f6d656e6665 = v1
    //let assert 0x6b7f62616d677361 = v2
    //let assert 0x7b6b696e727e6c7b = v3

    // Compression

    use #(v0, v1, v2, v3) <- result.try(
        iterator.fold(
            from: Ok(#(v0, v1, v2, v3)),
            over: iterator.iterate(0, fn (x) { x + message_block_length }) |> iterator.take({data_length - left_out_bytes_count} / message_block_length), // 0, 8, 16...
            with: fn (acc, position)
            {
                use message_block <- result.try(
                    {
                        use slice <- result.try(result.replace_error(bit_array.slice(at: position, from: data, take: int.min(8, data_length)), "gsiphash.siphash: couldn't get message block at position " <> int.to_string(position)))
                        i64_get(slice)
                    }
                )
                
                use #(v0, v1, v2, v3) <- result.try(acc)
                let v3 = int.bitwise_exclusive_or(v3, message_block)
                
                //let assert 0x7c6d6c6a717c6d7b = v3
                
                let #(v0, v1, v2, v3) = iterator.fold(
                    from: #(v0, v1, v2, v3),
                    over: iterator.range(1, c),
                    with: fn (acc, _)
                    {
                        let #(v0, v1, v2, v3) = acc
                        sip_round(v0, v1, v2, v3)
                    }
                )

                //let assert 0x4d07749cdd0858e0 = v0
                //let assert 0x0d52f6f62a4f59a4 = v1
                //let assert 0x634cb3577b01fd3d = v2
                //let assert 0xa5224d6f55c7d9c8 = v3

                let v0 = int.bitwise_exclusive_or(v0, message_block)

                //let assert 0x4a017198de0a59e0 = v0

                Ok(#(v0, v1, v2, v3))
            }
        )
    )

    // Compression from the last message block from the data. This process is similar
    // to the one above, but the last message block includes the last 7 bytes from the
    // data together the data's length.

    // The last message block from the data to be processed; the length
    // of the data must be placed in the highest byte (64 - 8 = 56).
    let last_message_block = i64_cast(int.bitwise_shift_left(data_length, 56))

    use last_message_block <- result.try(
        case left_out_bytes_count > 0
        {
            False -> Ok(last_message_block)
            True ->
            {
                // Fill last_message_block with the left out bytes, from LSB to MSB.
                //
                // Simple explanation:
                //
                // data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e}
                //         ^-- 1st message block                           ^-- 2nd message block (last message block)
                // data_length = 15 = 0x000000000000000f;
                // last_message_block = data_length << 56 = 0x0f00000000000000
                // When position = 0 then last_message_block = last_message_block OR 0x08 << 0  = 0x0f00000000000008
                // When position = 1 then last_message_block = last_message_block OR 0x09 << 8  = 0x0f00000000000908
                // When position = 2 then last_message_block = last_message_block OR 0x0a << 16 = 0x0f000000000a0908
                // When position = 4 then last_message_block = last_message_block OR 0x0b << 24 = 0x0f0000000b0a0908
                // When position = 5 then last_message_block = last_message_block OR 0x0c << 32 = 0x0f00000c0b0a0908
                // When position = 6 then last_message_block = last_message_block OR 0x0d << 40 = 0x0f000d0c0b0a0908
                // When position = 7 then last_message_block = last_message_block OR 0x0e << 48 = 0x0f0e0d0c0b0a0908

                iterator.fold(
                    from: Ok(last_message_block),
                    over: iterator.range(data_length - left_out_bytes_count, data_length - 1),
                    with: fn (acc, position)
                    {
                        use last_message_block <- result.try(acc)
                        use left_out_byte <- result.try(
                            {
                                use slice <- result.try(result.replace_error(bit_array.slice(at: position, from: data, take: 1), "gsiphash.siphash: couldn't get the left out byte at position " <> int.to_string(position)))
                                i64_get(slice)
                            }
                        )
                        let bits_to_shift = message_block_length * { position - { data_length - left_out_bytes_count }}
                        let last_message_block = int.bitwise_or(last_message_block, i64_cast(int.bitwise_shift_left(left_out_byte, bits_to_shift)))
                        Ok(last_message_block)
                    }
                )
            }
        }
    )

    //let assert 0x0f0e0d0c0b0a0908 = last_message_block

    let v3 = int.bitwise_exclusive_or(v3, last_message_block)
    let #(v0, v1, v2, v3) = iterator.fold(
        from: #(v0, v1, v2, v3),
        over: iterator.range(1, c),
        with: fn (acc, _)
        {
            let #(v0, v1, v2, v3) = acc
            sip_round(v0, v1, v2, v3)
        }
    )

    let v0 = int.bitwise_exclusive_or(v0, last_message_block)

    // Finalization

    let v2 = int.bitwise_exclusive_or(v2, 0xff)

    //let assert 0x3c85b3ab6f55be51 = v0
    //let assert 0x414fc3fb98efe374 = v1
    //let assert 0xccf13ea527b9f442 = v2
    //let assert 0x5293f5da84008f82 = v3

    let #(v0, v1, v2, v3) = iterator.fold(
        from: #(v0, v1, v2, v3),
        over: iterator.range(1, d),
        with: fn (acc, _)
        {
            let #(v0, v1, v2, v3) = acc
            sip_round(v0, v1, v2, v3)
        }
    )

    //let assert 0xf6bcd53893fecff1 = v0
    //let assert 0x54b9964c7ea0d937 = v1
    //let assert 0x1b38329c099bb55a = v2
    //let assert 0x1814bb89ad7be679 = v3

    let result = int.bitwise_exclusive_or(int.bitwise_exclusive_or(v0, v1), int.bitwise_exclusive_or(v2, v3))
    //let assert 0xa129ca6149be45e5 = result

    Ok(result)
}
