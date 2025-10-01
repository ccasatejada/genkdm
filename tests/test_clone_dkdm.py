from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from kdm.clone_dkdm import clone_dkdm_to_kdm, clone_dkdm_to_kdm_signed


class TestCloneDKDMToKDM:

    @patch('kdm.clone_dkdm.KDMGenerator')
    @patch('kdm.clone_dkdm.validate_kdm_xml')
    @patch('kdm.clone_dkdm.check_kdm_against_cpl')
    @patch('kdm.clone_dkdm.get_current_path')
    def test_clone_dkdm_to_kdm_success(self, mock_get_path, mock_check_cpl, mock_validate, mock_kdm_gen_class):
        # arrange
        mock_get_path.return_value = "/test/path"
        mock_kdm_gen = Mock()
        mock_kdm_gen_class.return_value = mock_kdm_gen
        mock_kdm_gen.generate_kdm.return_value = ("/test/output/kdm.xml", "<kdm>test</kdm>")
        mock_validate.return_value = True
        mock_check_cpl.return_value = True

        start_time = datetime(2024, 11, 4, 10, 0, 0)
        end_time = datetime(2024, 11, 6, 23, 59, 59)

        # act
        result = clone_dkdm_to_kdm(start_time, end_time)

        # assert
        mock_kdm_gen_class.assert_called_once_with(
            "/test/path/files/tmp/server_key.pem",
            "/test/path/files/self/full_chain.pem"
        )

        mock_kdm_gen.generate_kdm.assert_called_once_with(
            "/test/path/files/dkdm/kdm_Test_des_equipements_de_projection_VO_Varietes_Les_Melun_4_110425_110426.xml",
            "/test/path/files/certificate/certificate_chain.pem",
            start_time,
            end_time,
            "Test KDM from DKDM"
        )

        mock_validate.assert_called_once_with(
            "/test/output/kdm.xml",
            "/test/path/files/xsd/DCinemaSecurityMessage.xsd"
        )

        mock_check_cpl.assert_called_once_with(
            "/test/output/kdm.xml",
            "/test/path/files/cpl/CPL_de1058f8-6db8-49c2-9259-87c35e313490.xml"
        )

        assert result == "/test/output/kdm.xml"

    @patch('kdm.clone_dkdm.KDMGenerator')
    @patch('kdm.clone_dkdm.get_current_path')
    def test_clone_dkdm_to_kdm_kdm_generation_failure(self, mock_get_path, mock_kdm_gen_class):
        # arrange
        mock_get_path.return_value = "/test/path"
        mock_kdm_gen = Mock()
        mock_kdm_gen_class.return_value = mock_kdm_gen
        mock_kdm_gen.generate_kdm.side_effect = Exception("KDM generation failed")

        start_time = datetime(2024, 11, 4, 10, 0, 0)
        end_time = datetime(2024, 11, 6, 23, 59, 59)

        # act / assert
        with pytest.raises(Exception, match="KDM generation failed"):
            clone_dkdm_to_kdm(start_time, end_time)

    @patch('kdm.clone_dkdm.KDMGenerator')
    @patch('kdm.clone_dkdm.validate_kdm_xml')
    @patch('kdm.clone_dkdm.get_current_path')
    def test_clone_dkdm_to_kdm_validation_failure(self, mock_get_path, mock_validate, mock_kdm_gen_class):
        # arrange
        mock_get_path.return_value = "/test/path"
        mock_kdm_gen = Mock()
        mock_kdm_gen_class.return_value = mock_kdm_gen
        mock_kdm_gen.generate_kdm.return_value = ("/test/output/kdm.xml", "<kdm>test</kdm>")
        mock_validate.side_effect = Exception("Validation failed")

        start_time = datetime(2024, 11, 4, 10, 0, 0)
        end_time = datetime(2024, 11, 6, 23, 59, 59)

        # act / assert
        with pytest.raises(Exception, match="Validation failed"):
            clone_dkdm_to_kdm(start_time, end_time)

    @patch('kdm.clone_dkdm.clone_dkdm_to_kdm')
    @patch('kdm.clone_dkdm.sign_smpte_kdm')
    def test_clone_dkdm_to_kdm_signed_success(self, mock_sign, mock_clone):
        # arrange
        mock_clone.return_value = "/test/output/kdm.xml"
        mock_sign.return_value = "/test/output/kdm_signed.xml"

        # act
        result = clone_dkdm_to_kdm_signed(datetime.now(), datetime.now())

        # assert
        mock_clone.assert_called_once()
        mock_sign.assert_called_once_with("/test/output/kdm.xml")
        assert result == "/test/output/kdm_signed.xml"

    @patch('kdm.clone_dkdm.clone_dkdm_to_kdm')
    @patch('kdm.clone_dkdm.sign_smpte_kdm')
    def test_clone_dkdm_to_kdm_signed_signing_failure(self, mock_sign, mock_clone):
        # arrange
        mock_clone.return_value = "/test/output/kdm.xml"
        mock_sign.side_effect = Exception("Signing failed")

        # act
        result = clone_dkdm_to_kdm_signed(
            datetime.now(),
            datetime.now()
        )

        # assert
        mock_clone.assert_called_once()
        mock_sign.assert_called_once_with("/test/output/kdm.xml")
        assert result == "/test/output/kdm.xml"  # Should return unsigned KDM on signing failure
