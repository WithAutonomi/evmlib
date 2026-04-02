// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library MerklePaymentLib {
    /// Calculate expected number of reward pools: 2^ceil(depth/2)
    function expectedRewardPools(uint8 depth) internal pure returns (uint256) {
        uint8 halfDepth = (depth + 1) / 2; // ceil division
        return 1 << halfDepth; // 2^halfDepth
    }

    /// Select winner pool using deterministic pseudo-randomness
    function selectWinnerPool(
        uint256 poolCount,
        address sender,
        uint64 timestamp
    ) internal view returns (uint256) {
        bytes32 seed = keccak256(
            abi.encodePacked(
                block.prevrandao,
                block.timestamp,
                sender,
                timestamp
            )
        );
        return uint256(seed) % poolCount;
    }

    function selectWinnerNodes(
        uint8 depth,
        bytes32 poolHash,
        uint64 timestamp
    ) internal view returns (uint8[] memory) {
        uint8[] memory winners = new uint8[](depth);
        uint8[16] memory indices = [
            0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
        ];

        bytes32 seed = keccak256(
            abi.encodePacked(block.prevrandao, poolHash, timestamp)
        );

        uint8 byteIndex = 0;

        for (uint8 i = 0; i < depth; ++i) {
            // Expand seed only when we run out of bytes
            if (byteIndex == 32) {
                seed = keccak256(abi.encodePacked(seed));
                byteIndex = 0;
            }

            // Use a single byte as random number
            uint8 rnd = uint8(seed[byteIndex++]);

            uint8 j = uint8(i + (rnd % (16 - i)));

            // swap
            (indices[i], indices[j]) = (indices[j], indices[i]);

            winners[i] = indices[i];
        }

        return winners;
    }

    function median16(uint256[16] memory a) internal pure returns (uint256) {
        uint256 left = 0;
        uint256 right = 15; // fixed length - 1
        uint256 k = 8; // median index for 16 elements

        while (true) {
            uint256 pivot = a[(left + right) >> 1];
            uint256 i = left;
            uint256 j = right;

            // Partition
            while (i <= j) {
                while (a[i] < pivot) i++;

                while (pivot < a[j]) j--;

                if (i <= j) {
                    (a[i], a[j]) = (a[j], a[i]);
                    unchecked {
                        i++;
                        j--;
                    }
                }
            }

            // Narrow search region
            if (k <= j) {
                right = j;
            } else if (i <= k) {
                left = i;
            } else {
                return a[k];
            }
        }
        revert();
    }
}
